package fiberauth

import (
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// RefreshSession is an optional long-lived session that mints short
// access tokens (see Issue). The token rotates on every use; only its
// SHA-256 is stored. ID stays stable across rotations so the app looks
// the record up by it. The cookie value is "id:plainToken".
type RefreshSession struct {
	ID          string `json:"id"`
	UID         string `json:"uid"`
	Ver         int64  `json:"ver"`
	HashedToken string `json:"hashedToken"`
	// PrevHashedToken is the token replaced by the last rotation, still
	// accepted within the grace window (concurrent tabs refreshing).
	PrevHashedToken string    `json:"prevHashedToken,omitempty"`
	RotatedAt       time.Time `json:"rotatedAt"`
	Label           string    `json:"label"`
	CreatedAt       time.Time `json:"createdAt"`
	// ExpiresAt is absolute, rotation never extends it.
	ExpiresAt time.Time `json:"expiresAt"`
}

type RefreshResult int

const (
	RefreshOK      RefreshResult = iota // rotate, persist, set cookie, issue access token
	RefreshGrace                        // previous token within grace: issue access token only
	RefreshExpired                      // delete record, clear cookie
	RefreshRevoked                      // TokenVersion bumped since issuance: delete record, clear cookie
	RefreshReuse                        // token matches nothing: likely stolen, delete record and security-warn
)

// NewRefreshSession mints a session bound to uid and ver, the user's
// current TokenVersion, so bumping it revokes the session. plain goes
// in the cookie (see RefreshCookie), the returned record is persisted.
func NewRefreshSession(uid string, ver int64, label string, ttl time.Duration) (RefreshSession, string, error) {
	plain, err := randomHex(32)
	if err != nil {
		return RefreshSession{}, "", fmt.Errorf("generate refresh token: %w", err)
	}
	now := time.Now()
	return RefreshSession{
		ID:          uuid.New().String(),
		UID:         uid,
		Ver:         ver,
		HashedToken: hashToken(plain),
		RotatedAt:   now,
		Label:       label,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}, plain, nil
}

// RotateRefreshSession swaps in a fresh token, keeping the old hash for
// the grace window. Persist with a compare-and-swap on the old
// HashedToken so two concurrent rotations can't both win.
func RotateRefreshSession(s RefreshSession) (RefreshSession, string, error) {
	plain, err := randomHex(32)
	if err != nil {
		return RefreshSession{}, "", fmt.Errorf("generate refresh token: %w", err)
	}
	s.PrevHashedToken = s.HashedToken
	s.HashedToken = hashToken(plain)
	s.RotatedAt = time.Now()
	return s, plain, nil
}

// CheckRefresh validates plain against the stored session. currentVer
// is the user's stored TokenVersion; grace is how long the previous
// token stays usable after a rotation (a few seconds is plenty).
func CheckRefresh(s RefreshSession, plain string, currentVer int64, grace time.Duration) RefreshResult {
	now := time.Now()
	if !now.Before(s.ExpiresAt) {
		return RefreshExpired
	}
	if s.Ver < currentVer {
		return RefreshRevoked
	}
	h := []byte(hashToken(plain))
	if subtle.ConstantTimeCompare(h, []byte(s.HashedToken)) == 1 {
		return RefreshOK
	}
	if s.PrevHashedToken != "" && now.Sub(s.RotatedAt) <= grace &&
		subtle.ConstantTimeCompare(h, []byte(s.PrevHashedToken)) == 1 {
		return RefreshGrace
	}
	return RefreshReuse
}

// SplitRefreshCookie parses an "id:plainToken" cookie value.
func SplitRefreshCookie(v string) (id, plain string, ok bool) {
	id, plain, ok = strings.Cut(v, ":")
	if !ok || id == "" || plain == "" {
		return "", "", false
	}
	return id, plain, true
}

// RefreshCookie builds the refresh cookie. path should be the refresh
// endpoint so the cookie never rides normal API calls. HTTPOnly keeps
// it from JS, SameSite=Strict blocks cross-site (CSRF) refreshes.
func RefreshCookie(name, path, id, plain string, ttl time.Duration) *fiber.Cookie {
	return &fiber.Cookie{
		Name:     name,
		Value:    id + ":" + plain,
		MaxAge:   int(ttl.Seconds()),
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     path,
	}
}

// ExpiredRefreshCookie tells the browser to drop the refresh cookie.
// name and path must match RefreshCookie's.
func ExpiredRefreshCookie(name, path string) *fiber.Cookie {
	return &fiber.Cookie{
		Name:     name,
		Value:    "",
		MaxAge:   -1,
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     path,
	}
}
