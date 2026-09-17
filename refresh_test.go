package fiberauth

import (
	"testing"
	"time"
)

func TestCheckRefresh(t *testing.T) {
	s, plain, err := NewRefreshSession("uid1", 2, "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rotated, newPlain, err := RotateRefreshSession(s)
	if err != nil {
		t.Fatal(err)
	}
	staleRotation := rotated
	staleRotation.RotatedAt = time.Now().Add(-time.Minute)
	expired := s
	expired.ExpiresAt = time.Now().Add(-time.Second)

	cases := []struct {
		name  string
		s     RefreshSession
		plain string
		ver   int64
		want  RefreshResult
	}{
		{"fresh ok", s, plain, 2, RefreshOK},
		{"wrong token", s, "nope", 2, RefreshReuse},
		{"empty token", s, "", 2, RefreshReuse},
		{"expired", expired, plain, 2, RefreshExpired},
		{"revoked", s, plain, 3, RefreshRevoked},
		{"rotated new ok", rotated, newPlain, 2, RefreshOK},
		{"rotated old in grace", rotated, plain, 2, RefreshGrace},
		{"rotated old after grace", staleRotation, plain, 2, RefreshReuse},
	}
	for _, tc := range cases {
		if got := CheckRefresh(tc.s, tc.plain, tc.ver, 10*time.Second); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestRotateRefreshSessionKeepsIdentity(t *testing.T) {
	s, _, err := NewRefreshSession("uid1", 2, "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := RotateRefreshSession(s)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != s.ID || r.UID != s.UID || r.Ver != s.Ver || !r.CreatedAt.Equal(s.CreatedAt) || !r.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatalf("rotation changed identity: %+v -> %+v", s, r)
	}
	if r.HashedToken == s.HashedToken || r.PrevHashedToken != s.HashedToken {
		t.Fatal("rotation did not swap hashes")
	}
}

func TestSplitRefreshCookie(t *testing.T) {
	if id, plain, ok := SplitRefreshCookie("abc:def"); !ok || id != "abc" || plain != "def" {
		t.Fatalf("valid cookie: id=%q plain=%q ok=%v", id, plain, ok)
	}
	for _, v := range []string{"", "abc", ":def", "abc:"} {
		if _, _, ok := SplitRefreshCookie(v); ok {
			t.Errorf("%q: want ok=false", v)
		}
	}
}

func TestRefreshCookie(t *testing.T) {
	c := RefreshCookie("rt", "/api/auth/refresh", "id", "tok", time.Hour)
	if c.Value != "id:tok" || !c.HTTPOnly || c.SameSite != "Strict" || c.Path != "/api/auth/refresh" || c.MaxAge != 3600 {
		t.Fatalf("bad cookie: %+v", c)
	}
	e := ExpiredRefreshCookie("rt", "/api/auth/refresh")
	if e.Name != c.Name || e.Path != c.Path || !e.HTTPOnly || e.SameSite != "Strict" || e.MaxAge != -1 {
		t.Fatalf("expired cookie attributes mismatch: %+v", e)
	}
}
