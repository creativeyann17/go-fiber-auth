package fiberauth

import (
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func testDevice(t *testing.T, ttl time.Duration) (TrustedDevice, string) {
	t.Helper()
	id, plain, hashed, err := NewTrustedDeviceToken()
	if err != nil {
		t.Fatal(err)
	}
	d := TrustedDevice{
		ID:          id,
		HashedToken: hashed,
		Label:       "test",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
	}
	return d, id + ":" + plain
}

func TestValidateDeviceCookie(t *testing.T) {
	d, cookie := testDevice(t, time.Hour)
	devices := []TrustedDevice{d}

	if id, ok := ValidateDeviceCookie(cookie, devices); !ok || id != d.ID {
		t.Fatalf("valid cookie rejected: id=%q ok=%v", id, ok)
	}
	if _, ok := ValidateDeviceCookie(d.ID+":wrong-token", devices); ok {
		t.Fatal("wrong token accepted")
	}
	if _, ok := ValidateDeviceCookie("malformed", devices); ok {
		t.Fatal("malformed cookie accepted")
	}
	if _, ok := ValidateDeviceCookie(cookie, nil); ok {
		t.Fatal("cookie accepted with no devices")
	}
}

func TestValidateDeviceCookie_Expired(t *testing.T) {
	d, cookie := testDevice(t, -time.Minute)
	if _, ok := ValidateDeviceCookie(cookie, []TrustedDevice{d}); ok {
		t.Fatal("expired device accepted")
	}
}

func TestPruneExpiredDevices(t *testing.T) {
	live, _ := testDevice(t, time.Hour)
	dead, _ := testDevice(t, -time.Minute)
	out := PruneExpiredDevices([]TrustedDevice{dead, live, dead})
	if len(out) != 1 || out[0].ID != live.ID {
		t.Fatalf("want only live device, got %d entries", len(out))
	}
}

func TestCookieDeviceID(t *testing.T) {
	if got := CookieDeviceID("abc:tok"); got != "abc" {
		t.Fatalf("got %q want %q", got, "abc")
	}
	if got := CookieDeviceID("no-separator"); got != "" {
		t.Fatalf("malformed cookie: got %q want empty", got)
	}
	if got := CookieDeviceID(""); got != "" {
		t.Fatalf("empty cookie: got %q want empty", got)
	}
}

func TestDeviceCookieRoundTrip(t *testing.T) {
	ck := DeviceCookie("app_device", "id1", "tok1", time.Hour)
	if ck.Value != "id1:tok1" || !ck.HTTPOnly || ck.SameSite != "Strict" || ck.MaxAge != 3600 {
		t.Fatalf("bad cookie: %+v", ck)
	}
	dead := ExpiredDeviceCookie("app_device")
	if dead.MaxAge != -1 || dead.Value != "" || dead.Path != ck.Path || dead.SameSite != ck.SameSite {
		t.Fatalf("expiry cookie must match original attributes: %+v", dead)
	}
}

func TestDeviceCookieAttributes(t *testing.T) {
	c := DeviceCookie("dev", "id", "tok", time.Hour)
	e := ExpiredDeviceCookie("dev")
	for _, ck := range []*fiber.Cookie{c, e} {
		if !ck.HTTPOnly || !ck.Secure || ck.SameSite != "Strict" || ck.Path != "/" {
			t.Fatalf("bad device cookie attributes: %+v", ck)
		}
	}
}
