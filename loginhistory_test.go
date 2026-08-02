package fiberauth

import (
	"strings"
	"testing"
	"time"
)

func TestIsNewIP_EmptyHistory(t *testing.T) {
	if IsNewIP("1.2.3.4", nil) {
		t.Fatal("first login must not be flagged as new IP")
	}
}

func TestIsNewIP_KnownIP(t *testing.T) {
	h := []LoginRecord{{IP: "1.2.3.4", At: time.Now()}}
	if IsNewIP("1.2.3.4", h) {
		t.Fatal("known IP flagged as new")
	}
}

func TestIsNewIP_UnknownIP(t *testing.T) {
	h := []LoginRecord{{IP: "1.2.3.4", At: time.Now()}}
	if !IsNewIP("5.6.7.8", h) {
		t.Fatal("unknown IP not flagged")
	}
}

func TestAppendLoginRecord_NewestFirstAndCapped(t *testing.T) {
	var h []LoginRecord
	for i := range 12 {
		h = AppendLoginRecord(h, "10.0.0.1", "ua", 10)
		if h[0].At.IsZero() {
			t.Fatalf("record %d missing timestamp", i)
		}
	}
	if len(h) != 10 {
		t.Fatalf("history must cap at 10, got %d", len(h))
	}
	h = AppendLoginRecord(h, "99.9.9.9", "ua", 10)
	if h[0].IP != "99.9.9.9" {
		t.Fatal("newest record must be first")
	}
	if len(h) != 10 {
		t.Fatalf("cap violated after prepend: %d", len(h))
	}
}

func TestAppendLoginRecord_TruncatesUserAgent(t *testing.T) {
	h := AppendLoginRecord(nil, "1.1.1.1", strings.Repeat("x", 500), 10)
	if got := len([]rune(h[0].UserAgent)); got != 120 {
		t.Fatalf("UA must truncate to 120 runes, got %d", got)
	}
}
