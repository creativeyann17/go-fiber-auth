package fiberauth

import (
	"strings"
	"testing"
	"time"
)

const testSecret = "test-secret-32bytesxxxxxxxxxx!!"

func TestIssueAndParse(t *testing.T) {
	tok, err := Issue(testSecret, "uid1", []string{"admin", "user"}, 3, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := Parse(testSecret, tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if claims.UID != "uid1" {
		t.Fatalf("UID: got %q want %q", claims.UID, "uid1")
	}
	if !claims.HasRole("admin") || !claims.HasRole("user") || claims.HasRole("root") {
		t.Fatalf("HasRole wrong: roles=%v", claims.Roles)
	}
	if claims.Ver != 3 {
		t.Fatalf("Ver: got %d want 3", claims.Ver)
	}
	if claims.Purpose != "" {
		t.Fatalf("session token must have empty Purpose, got %q", claims.Purpose)
	}
}

func TestParseWrongSecret(t *testing.T) {
	tok, err := Issue(testSecret, "uid1", []string{"user"}, 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse("different-secret-32bytesxxxxxxxx", tok); err == nil {
		t.Fatal("expected error with wrong secret, got nil")
	}
}

func TestParseExpired(t *testing.T) {
	tok, err := Issue(testSecret, "uid1", []string{"user"}, 0, -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(testSecret, tok); err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestParseTamperedSignature(t *testing.T) {
	tok, err := Issue(testSecret, "uid1", []string{"user"}, 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected JWT format: %d parts", len(parts))
	}
	sig := []byte(parts[2])
	sig[len(sig)-1] ^= 0xff
	parts[2] = string(sig)
	if _, err = Parse(testSecret, strings.Join(parts, ".")); err == nil {
		t.Fatal("expected error for tampered signature, got nil")
	}
}

func TestIssuePurpose(t *testing.T) {
	tok, err := IssuePurpose(testSecret, "uid1", "pwreset", 7, time.Hour)
	if err != nil {
		t.Fatalf("IssuePurpose: %v", err)
	}
	claims, err := Parse(testSecret, tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if claims.Purpose != "pwreset" {
		t.Fatalf("Purpose: got %q want %q", claims.Purpose, "pwreset")
	}
	if claims.Ver != 7 {
		t.Fatalf("Ver: got %d want 7 (must bind to TokenVersion at issuance)", claims.Ver)
	}
	if len(claims.Roles) != 0 {
		t.Fatalf("purpose token must carry no roles, got %v", claims.Roles)
	}
}

func TestVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "correct-horse") {
		t.Fatal("VerifyPassword returned false for correct password")
	}
	if VerifyPassword(hash, "wrong-horse") {
		t.Fatal("VerifyPassword returned true for wrong password")
	}
	if VerifyPassword(hash, "") {
		t.Fatal("VerifyPassword returned true for empty password")
	}
}
