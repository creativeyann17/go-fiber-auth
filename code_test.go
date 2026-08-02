package fiberauth

import (
	"testing"
	"time"
)

func future() *time.Time { t := time.Now().Add(time.Hour); return &t }
func past() *time.Time   { t := time.Now().Add(-time.Hour); return &t }

func TestGenerateCode(t *testing.T) {
	seen := map[string]bool{}
	for range 20 {
		code, err := GenerateCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 6 {
			t.Fatalf("want 6 digits, got %q", code)
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("non-digit in code %q", code)
			}
		}
		seen[code] = true
	}
	if len(seen) < 2 {
		t.Fatal("20 generated codes all identical, RNG broken")
	}
}

func TestCheckCode_OK(t *testing.T) {
	st := CodeState{Code: "123456", ExpiresAt: future(), Attempts: 0}
	if res, _ := CheckCode(st, "123456", 5); res != CodeOK {
		t.Fatalf("want CodeOK, got %v", res)
	}
}

func TestCheckCode_Wrong(t *testing.T) {
	st := CodeState{Code: "123456", ExpiresAt: future(), Attempts: 2}
	res, remaining := CheckCode(st, "000000", 5)
	if res != CodeWrong {
		t.Fatalf("want CodeWrong, got %v", res)
	}
	// 2 prior attempts + this failure = 3 used, 2 left of 5.
	if remaining != 2 {
		t.Fatalf("remaining: got %d want 2", remaining)
	}
}

func TestCheckCode_EmptyInputIsWrong(t *testing.T) {
	st := CodeState{Code: "123456", ExpiresAt: future()}
	if res, _ := CheckCode(st, "", 5); res != CodeWrong {
		t.Fatalf("empty input: want CodeWrong, got %v", res)
	}
}

func TestCheckCode_Expired(t *testing.T) {
	for _, st := range []CodeState{
		{Code: "123456", ExpiresAt: past()},
		{Code: "123456", ExpiresAt: nil},
		{Code: "", ExpiresAt: future()},
	} {
		if res, _ := CheckCode(st, "123456", 5); res != CodeExpired {
			t.Fatalf("state %+v: want CodeExpired, got %v", st, res)
		}
	}
}

func TestCheckCode_Locked(t *testing.T) {
	st := CodeState{Code: "123456", ExpiresAt: future(), Attempts: 5}
	// Even the correct code is rejected once the budget is spent.
	if res, _ := CheckCode(st, "123456", 5); res != CodeLocked {
		t.Fatalf("want CodeLocked, got %v", res)
	}
}

func TestCheckCode_RemainingFloorsAtZero(t *testing.T) {
	st := CodeState{Code: "123456", ExpiresAt: future(), Attempts: 4}
	res, remaining := CheckCode(st, "000000", 5)
	if res != CodeWrong || remaining != 0 {
		t.Fatalf("got %v remaining=%d, want CodeWrong remaining=0", res, remaining)
	}
}
