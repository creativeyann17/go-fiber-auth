package fiberauth

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

// GenerateCode returns a cryptographically random 6-digit string used
// for email verification and password-reset codes (leading zeros
// allowed: argue about entropy, not display width).
func GenerateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// CodeState mirrors the three fields apps persist per code flow on their
// user record (code, expiry, wrong-attempt counter). Plain data in, the
// caller owns storage.
type CodeState struct {
	Code      string
	ExpiresAt *time.Time
	Attempts  int
}

type CodeCheck int

const (
	// CodeOK: input matches. Caller clears the three fields and persists.
	CodeOK CodeCheck = iota
	// CodeExpired: no code pending or past expiry. Caller prompts a resend.
	CodeExpired
	// CodeLocked: attempt budget exhausted. Only issuing a fresh code
	// (which resets Attempts) unlocks.
	CodeLocked
	// CodeWrong: mismatch. Caller increments Attempts and persists.
	CodeWrong
)

// CheckCode runs the shared validation decision tree for 6-digit email
// codes. Pure: the caller mutates its record per the result (increment
// Attempts on CodeWrong, clear fields on CodeOK) and persists.
// remaining is only meaningful for CodeWrong: attempts left after this
// failure, floored at 0.
func CheckCode(st CodeState, input string, maxAttempts int) (result CodeCheck, remaining int) {
	if st.Code == "" || st.ExpiresAt == nil || time.Now().After(*st.ExpiresAt) {
		return CodeExpired, 0
	}
	if st.Attempts >= maxAttempts {
		return CodeLocked, 0
	}
	if input == "" || input != st.Code {
		return CodeWrong, max(maxAttempts-st.Attempts-1, 0)
	}
	return CodeOK, 0
}
