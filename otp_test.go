package fiberauth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateTOTPSecretAndValidate(t *testing.T) {
	secret, uri, err := GenerateTOTPSecret(TOTPConfig{Issuer: "Test App"}, "alice")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if secret == "" || uri == "" {
		t.Fatalf("empty secret/uri: %q %q", secret, uri)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateTOTPCode(secret, code) {
		t.Fatal("valid code rejected")
	}
	if ValidateTOTPCode(secret, "000000") && code != "000000" {
		t.Fatal("wrong code accepted")
	}
}

func TestGenerateBackupCodes(t *testing.T) {
	plain, hashed, err := GenerateBackupCodes(8)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}
	if len(plain) != 8 || len(hashed) != 8 {
		t.Fatalf("want 8 codes, got %d plain %d hashed", len(plain), len(hashed))
	}
	for i, p := range plain {
		if len(p) != 10 {
			t.Fatalf("code %d: want 10 hex chars, got %q", i, p)
		}
	}
}

func TestCheckBackupCode(t *testing.T) {
	plain, hashed, err := GenerateBackupCodes(3)
	if err != nil {
		t.Fatal(err)
	}
	idx, ok := CheckBackupCode(hashed, plain[1])
	if !ok || idx != 1 {
		t.Fatalf("want match at 1, got idx=%d ok=%v", idx, ok)
	}
	if _, ok := CheckBackupCode(hashed, "not-a-code!"); ok {
		t.Fatal("bogus code accepted")
	}
	// One-time use is the caller's contract: removing the matched index
	// makes the same code fail next time.
	hashed = append(hashed[:idx], hashed[idx+1:]...)
	if _, ok := CheckBackupCode(hashed, plain[1]); ok {
		t.Fatal("consumed code must not match again")
	}
}
