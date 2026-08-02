package fiberauth

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type TOTPConfig struct {
	Issuer string // shown in authenticator apps, e.g. "Mist Drive"
}

// GenerateTOTPSecret mints a fresh TOTP secret and its otpauth:// URI
// (QR-code source) for accountName. Nothing is persisted: the app stores
// the secret only after the user proves enrollment via ValidateTOTPCode.
func GenerateTOTPSecret(cfg TOTPConfig, accountName string) (secret, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      cfg.Issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTPCode checks a 6-digit authenticator code against secret.
func ValidateTOTPCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes returns n one-time recovery codes (10 hex chars
// each) in plaintext, shown to the user exactly once, plus their bcrypt
// hashes for storage.
func GenerateBackupCodes(n int) (plaintext []string, hashed []string, err error) {
	for range n {
		b := make([]byte, 5)
		if _, err = rand.Read(b); err != nil {
			return nil, nil, err
		}
		code := hex.EncodeToString(b)
		h, e := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if e != nil {
			return nil, nil, e
		}
		plaintext = append(plaintext, code)
		hashed = append(hashed, string(h))
	}
	return plaintext, hashed, nil
}

// CheckBackupCode tests input against the stored bcrypt-hashed codes.
// On a match the caller must remove hashed[matchIndex] from their slice
// and persist immediately, single-use, crash-safe against replay.
func CheckBackupCode(hashed []string, input string) (matchIndex int, ok bool) {
	for i, h := range hashed {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(input)) == nil {
			return i, true
		}
	}
	return -1, false
}
