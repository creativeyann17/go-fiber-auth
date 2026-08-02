# go-fiber-auth

[![CI](https://github.com/creativeyann17/go-fiber-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/creativeyann17/go-fiber-auth/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/creativeyann17/go-fiber-auth.svg)](https://pkg.go.dev/github.com/creativeyann17/go-fiber-auth)
[![Go Version](https://img.shields.io/github/go-mod/go-version/creativeyann17/go-fiber-auth)](go.mod)
[![Release](https://img.shields.io/github/v/tag/creativeyann17/go-fiber-auth?label=release)](https://github.com/creativeyann17/go-fiber-auth/tags)
[![License](https://img.shields.io/github/license/creativeyann17/go-fiber-auth)](LICENSE)

Shared auth building blocks for [Fiber](https://github.com/gofiber/fiber) apps:
JWT sessions with token-version revocation, login throttling, TOTP 2FA,
trusted devices, single-use tickets, 6-digit email codes, and a Resend mail
client.

Storage-agnostic by design: every function takes closures or plain data, your
app owns persistence. No database driver, no ORM, no assumptions about your
user model.

## Install

```bash
go get github.com/creativeyann17/go-fiber-auth
```

```go
import fiberauth "github.com/creativeyann17/go-fiber-auth"
```

## Features

| File | What it gives you |
|---|---|
| `jwt.go` | HS256 session tokens (`Claims` with `UID`, `Roles`, `Ver`, `Purpose`), bcrypt password hashing, timing-attack `DummyVerify` |
| `throttle.go` | Keyed in-memory lockout (`Throttle`) + two-dimension login throttle (`LoginThrottle`: per-account and per-IP) |
| `middleware.go` | `AuthMiddleware`, `AdminOnly`, `TokenVersionMiddleware`, context accessors, `ClientIP` |
| `otp.go` | TOTP secret enrollment, code validation, bcrypt-hashed one-time backup codes |
| `trusteddevice.go` | "Remember this device" cookies (SHA-256 tokens, constant-time compare) |
| `ticket.go` | Single-use short-lived tickets so browser navigations never carry the JWT in a URL |
| `code.go` | Crypto-random 6-digit codes + the expiry/attempt-lockout validation state machine |
| `mailer.go` | Minimal [Resend](https://resend.com) client (no-op without an API key, dev-friendly) |
| `loginhistory.go` | Capped login history + new-IP detection for alert emails |

## Usage

### Sessions

```go
// Signup / login
hash, _ := fiberauth.HashPassword(password)
ok := fiberauth.VerifyPassword(hash, password)

tok, _ := fiberauth.Issue(secret, user.ID, []string{"user"}, user.TokenVersion, 24*time.Hour)

// Unknown-login path: burn a bcrypt compare so response timing
// doesn't reveal whether the account exists.
fiberauth.DummyVerify(password)
```

### Middleware

```go
app := fiber.New()

api := app.Group("/api",
    // bootTime rejects tokens issued before this process started.
    // onReject fires on suspicious rejections (bad signature, alg
    // confusion, malformed, purpose token) for your security log.
    fiberauth.AuthMiddleware(secret, bootTime, func(reason string, c *fiber.Ctx) {
        log.Warn("auth: "+reason, "ip", c.IP())
    }),
    // Revoke-everywhere: reject tokens older than the stored version.
    fiberauth.TokenVersionMiddleware(func(uid string) (int64, bool, error) {
        u, err := store.GetByID(uid)
        if err != nil {
            return 0, false, err
        }
        return u.TokenVersion, true, nil
    }),
)

api.Get("/me", func(c *fiber.Ctx) error {
    uid := fiberauth.UID(c) // also: Roles(c), Ver(c), HasRole(c, role)
    // ...
})

admin := api.Group("/admin", fiberauth.AdminOnly)
```

Bumping the stored `TokenVersion` (logout-all, password reset, ban) instantly
invalidates every outstanding token for that user.

### Login throttling

```go
guard := fiberauth.NewLoginThrottle(fiberauth.LoginThrottleConfig{})
// defaults: 5 fails/account, 20 fails/IP, 15m lockout, 1h TTL

if locked, retry := guard.Locked(login, fiberauth.ClientIP(c)); locked {
    c.Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
    return fiber.NewError(fiber.StatusTooManyRequests, "too many attempts")
}
// on failure:
count := guard.Fail(login, fiberauth.ClientIP(c)) // count paces alert emails
// on success:
guard.Succeeded(login) // clears the account counter; IP budget ages out via TTL

// Simple keyed variant for signup/resend/forgot-password spam guards:
signupGuard := fiberauth.NewThrottle(time.Hour, 6*time.Hour)
signupGuard.Fail("ip:"+ip, 10)
```

### TOTP 2FA

```go
// Enrollment: generate, let the user scan the QR (uri), then verify
// one code BEFORE persisting the secret.
secret, uri, _ := fiberauth.GenerateTOTPSecret(fiberauth.TOTPConfig{Issuer: "My App"}, user.Login)
if !fiberauth.ValidateTOTPCode(secret, code) { /* reject */ }

plain, hashed, _ := fiberauth.GenerateBackupCodes(8)
// store `hashed`, show `plain` exactly once

// Login with backup-code fallback:
if fiberauth.ValidateTOTPCode(user.TOTPSecret, code) { /* ok */ }
if i, ok := fiberauth.CheckBackupCode(user.TOTPBackupCodes, code); ok {
    // single-use: remove index i and persist IMMEDIATELY (replay safety)
    user.TOTPBackupCodes = append(user.TOTPBackupCodes[:i], user.TOTPBackupCodes[i+1:]...)
}
```

### Trusted devices (skip 2FA on known browsers)

```go
id, plain, hashed, _ := fiberauth.NewTrustedDeviceToken()
user.TrustedDevices = append(fiberauth.PruneExpiredDevices(user.TrustedDevices),
    fiberauth.TrustedDevice{ID: id, HashedToken: hashed, Label: ua,
        CreatedAt: time.Now(), ExpiresAt: time.Now().Add(30 * 24 * time.Hour)})
c.Cookie(fiberauth.DeviceCookie("app_device", id, plain, 30*24*time.Hour))

// At login:
if _, ok := fiberauth.ValidateDeviceCookie(c.Cookies("app_device"), user.TrustedDevices); ok {
    // skip the TOTP step
}

// Revocation:
c.Cookie(fiberauth.ExpiredDeviceCookie("app_device"))
```

### Single-use download tickets

Browser navigations (zip downloads, file streams) can't set an
`Authorization` header, and putting the JWT in a URL leaks it into access
logs. Mint a ticket instead:

```go
tickets := fiberauth.NewTicketStore(60 * time.Second)

// authenticated endpoint:
tok, _ := tickets.Issue(uid, "folder/photos")
// client then navigates to /download?ticket=<tok>

// public endpoint:
uid, scope, ok := tickets.Consume(c.Query("ticket")) // consumed on first use, replay fails
```

### Email codes (verification / password reset)

```go
code, _ := fiberauth.GenerateCode() // crypto-random "042917"
// store code + expiry + attempts=0 on your user record, email it

st := fiberauth.CodeState{Code: u.VerifyCode, ExpiresAt: u.VerifyExpiresAt, Attempts: u.VerifyAttempts}
switch res, remaining := fiberauth.CheckCode(st, input, 5); res {
case fiberauth.CodeOK:      // clear the three fields, mark verified
case fiberauth.CodeExpired: // prompt a resend
case fiberauth.CodeLocked:  // attempt budget spent; only a fresh code unlocks
case fiberauth.CodeWrong:   // increment Attempts, persist; `remaining` left
}
```

### Single-purpose tokens (reset links)

```go
// Bound to the current TokenVersion: bumping it after use kills replays,
// and AuthMiddleware never accepts a Purpose token as a session.
tok, _ := fiberauth.IssuePurpose(secret, user.ID, "pwreset", user.TokenVersion, 30*time.Minute)

claims, err := fiberauth.Parse(secret, tok)
if err != nil || claims.Purpose != "pwreset" || claims.Ver != user.TokenVersion { /* reject */ }
user.TokenVersion++ // burns the link and every other session
```

### Mailer (Resend)

```go
m := fiberauth.NewMailer(os.Getenv("RESEND_API_KEY"), "noreply@example.com")
if !m.Enabled() {
    log.Info("mail disabled, code for %s: %s", email, code) // dev fallback
}
_ = m.Send(email, "Your verification code", "<p>042917</p>")
```

## Development

```bash
make check         # gofmt + vet + race tests
make install-hooks # pre-commit hook running the same
```

## License

MIT
