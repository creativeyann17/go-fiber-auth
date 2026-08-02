// Package fiberauth provides the shared auth building blocks used by
// creativeyann17's Fiber apps: JWT sessions with TokenVersion revocation,
// login throttling, TOTP 2FA, trusted devices, single-use tickets,
// 6-digit email codes, and a Resend mail client. Storage-agnostic: every
// piece that touches a user record takes closures or plain data.
package fiberauth

import (
	"errors"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	UID   string   `json:"uid"`
	Roles []string `json:"roles"`
	Ver   int64    `json:"ver,omitempty"`
	// Purpose marks single-purpose tokens (e.g. "pwreset") that must never
	// be accepted as a normal session bearer token. Empty = regular session.
	Purpose string `json:"purp,omitempty"`
	jwt.RegisteredClaims
}

// HasRole reports whether the token's Roles claim carries r, the token
// is the sole source of truth for role checks on a request (see
// AuthMiddleware), never re-checked against the user store per-request.
func (c *Claims) HasRole(r string) bool {
	return slices.Contains(c.Roles, r)
}

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func VerifyPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// dummyHash is a valid bcrypt hash computed once at startup. It exists
// only so DummyVerify can burn a real bcrypt comparison.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equalizer"), bcrypt.DefaultCost)

// DummyVerify spends a bcrypt comparison against a throwaway hash. Call
// it on the unknown-login path so the response latency matches the
// wrong-password path, denying an attacker a timing oracle for
// username/email enumeration. The result is intentionally discarded.
func DummyVerify(pw string) {
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
}

func Issue(secret, uid string, roles []string, ver int64, ttl time.Duration) (string, error) {
	c := Claims{
		UID:   uid,
		Roles: roles,
		Ver:   ver,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(secret))
}

// IssuePurpose mints a single-purpose token (e.g. a password-reset link)
// bound to ver, the caller's current TokenVersion at issuance, so
// bumping TokenVersion after use invalidates any replay of this exact
// token without needing separate token storage. Never accepted by
// AuthMiddleware as a session token (see Purpose check there).
func IssuePurpose(secret, uid, purpose string, ver int64, ttl time.Duration) (string, error) {
	c := Claims{
		UID:     uid,
		Ver:     ver,
		Purpose: purpose,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(secret))
}

func Parse(secret, token string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("bad alg")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token")
	}
	return c, nil
}
