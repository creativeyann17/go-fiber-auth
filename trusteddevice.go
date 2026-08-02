package fiberauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// TrustedDevice is a "remember this device" record letting a browser
// skip the TOTP step. The cookie value is "id:plainToken"; only the
// SHA-256 of the token is stored.
type TrustedDevice struct {
	ID          string    `json:"id"`
	HashedToken string    `json:"hashedToken"`
	Label       string    `json:"label"`
	CreatedAt   time.Time `json:"createdAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// NewTrustedDeviceToken mints a device id plus its secret token. plain
// goes in the cookie (via DeviceCookie), hashed in the stored record.
func NewTrustedDeviceToken() (id, plain, hashed string, err error) {
	id = uuid.New().String()
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", err
	}
	plain = hex.EncodeToString(b)
	h := sha256.Sum256([]byte(plain))
	hashed = hex.EncodeToString(h[:])
	return id, plain, hashed, nil
}

// ValidateDeviceCookie checks a cookie value against the stored devices:
// constant-time token compare plus expiry check.
func ValidateDeviceCookie(cookieValue string, devices []TrustedDevice) (deviceID string, ok bool) {
	parts := strings.SplitN(cookieValue, ":", 2)
	if len(parts) != 2 {
		return "", false
	}
	id, plain := parts[0], parts[1]
	h := sha256.Sum256([]byte(plain))
	hashed := hex.EncodeToString(h[:])
	now := time.Now()
	for _, d := range devices {
		if d.ID == id && subtle.ConstantTimeCompare([]byte(d.HashedToken), []byte(hashed)) == 1 && now.Before(d.ExpiresAt) {
			return id, true
		}
	}
	return "", false
}

// PruneExpiredDevices drops expired entries in place.
func PruneExpiredDevices(devices []TrustedDevice) []TrustedDevice {
	now := time.Now()
	out := devices[:0]
	for _, d := range devices {
		if now.Before(d.ExpiresAt) {
			out = append(out, d)
		}
	}
	return out
}

// CookieDeviceID returns the device id embedded in a cookie value, or
// "" if absent/malformed.
func CookieDeviceID(cookieValue string) string {
	if parts := strings.SplitN(cookieValue, ":", 2); len(parts) == 2 && cookieValue != "" {
		return parts[0]
	}
	return ""
}

// DeviceCookie builds the trusted-device cookie for a freshly minted
// token. HTTPOnly + SameSite=Strict: the token never reaches JS and
// never rides a cross-site request.
func DeviceCookie(name, id, plain string, ttl time.Duration) *fiber.Cookie {
	return &fiber.Cookie{
		Name:     name,
		Value:    id + ":" + plain,
		MaxAge:   int(ttl.Seconds()),
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/",
	}
}

// ExpiredDeviceCookie tells the browser to drop the trusted-device
// cookie immediately. Attributes must match DeviceCookie's so the
// browser targets the same cookie.
func ExpiredDeviceCookie(name string) *fiber.Cookie {
	return &fiber.Cookie{
		Name:     name,
		Value:    "",
		MaxAge:   -1,
		HTTPOnly: true,
		SameSite: "Strict",
		Path:     "/",
	}
}
