package fiberauth

import (
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type ctxKey string

const (
	CtxUID   ctxKey = "uid"
	CtxRoles ctxKey = "roles"
	CtxVer   ctxKey = "ver"
)

// RoleAdmin is the shared role-name convention across apps.
const RoleAdmin = "admin"

// UID returns the authenticated user id set by AuthMiddleware, or "".
func UID(c *fiber.Ctx) string {
	v, _ := c.Locals(CtxUID).(string)
	return v
}

// Roles returns the token's roles set by AuthMiddleware, or nil.
func Roles(c *fiber.Ctx) []string {
	v, _ := c.Locals(CtxRoles).([]string)
	return v
}

// Ver returns the token's version claim set by AuthMiddleware, or 0.
func Ver(c *fiber.Ctx) int64 {
	v, _ := c.Locals(CtxVer).(int64)
	return v
}

// HasRole reports whether the request's token carries role r.
func HasRole(c *fiber.Ctx, r string) bool {
	return slices.Contains(Roles(c), r)
}

// AuthMiddleware validates the bearer token and stashes its claims in
// request locals. Header-only: tokens never ride in a URL, keeping them
// out of access logs (use TicketStore for browser-navigation downloads).
//
// onReject, nil-safe, receives a short reason string for security-warn
// logging on suspicious rejections (bad signature, alg confusion,
// malformed, purpose token). Expired tokens are normal, no callback.
//
// Tokens issued before bootTime are rejected, forcing re-login after a
// restart/redeployment.
func AuthMiddleware(secret string, bootTime time.Time, onReject func(reason string, c *fiber.Ctx)) fiber.Handler {
	warn := func(reason string, c *fiber.Ctx) {
		if onReject != nil {
			onReject(reason, c)
		}
	}
	return func(c *fiber.Ctx) error {
		h := c.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			return fiber.NewError(fiber.StatusUnauthorized, "missing bearer token")
		}
		tok := strings.TrimPrefix(h, "Bearer ")
		claims, err := Parse(secret, tok)
		if err != nil {
			switch {
			case errors.Is(err, jwt.ErrTokenSignatureInvalid):
				warn("invalid signature", c)
			case errors.Is(err, jwt.ErrTokenUnverifiable):
				// ErrTokenUnverifiable wraps our "bad alg" keyfunc error: algorithm confusion attempt.
				warn("bad algorithm", c)
			case errors.Is(err, jwt.ErrTokenMalformed):
				warn("malformed token", c)
				// ErrTokenExpired is normal, user just needs to re-login, no warn.
			}
			return fiber.NewError(fiber.StatusUnauthorized, "invalid token")
		}
		// A single-purpose token (password reset link etc.) is never a
		// session credential.
		if claims.Purpose != "" {
			warn("purpose token used as session", c)
			return fiber.NewError(fiber.StatusUnauthorized, "invalid token")
		}
		// Reject tokens issued before this server instance started.
		// Forces re-login after a restart/redeployment.
		if claims.IssuedAt == nil || claims.IssuedAt.Time.Before(bootTime) {
			return fiber.NewError(fiber.StatusUnauthorized, "session expired, please log in again")
		}
		c.Locals(CtxUID, claims.UID)
		c.Locals(CtxRoles, claims.Roles)
		c.Locals(CtxVer, claims.Ver)
		return c.Next()
	}
}

// AdminOnly gates a route to tokens carrying RoleAdmin.
func AdminOnly(c *fiber.Ctx) error {
	if !HasRole(c, RoleAdmin) {
		return fiber.NewError(fiber.StatusForbidden, "admin only")
	}
	return c.Next()
}

// TokenVersionMiddleware rejects tokens older than the user's current
// TokenVersion (bumped on logout-all/password reset/ban). lookup fetches
// the stored version for uid; found=false or an error rejects the
// request, treating a missing user as a revoked session.
func TokenVersionMiddleware(lookup func(uid string) (currentVersion int64, found bool, err error)) fiber.Handler {
	return func(c *fiber.Ctx) error {
		cur, found, err := lookup(UID(c))
		if err != nil || !found || Ver(c) < cur {
			return fiber.NewError(fiber.StatusUnauthorized, "session revoked")
		}
		return c.Next()
	}
}

// ClientIP returns the best available client IP: X-Forwarded-For when
// behind a trusted reverse proxy (see fiber.Config.ProxyHeader), falling
// back to the raw TCP remote address in local dev. Returns "unknown"
// when nothing is resolvable, the sentinel LoginThrottle skips.
func ClientIP(c *fiber.Ctx) string {
	if ip := c.IP(); ip != "" {
		return ip
	}
	if addr := c.Context().RemoteAddr(); addr != nil {
		if host, _, err := net.SplitHostPort(addr.String()); err == nil && host != "" {
			return host
		}
	}
	return "unknown"
}
