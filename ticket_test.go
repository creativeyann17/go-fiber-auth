package fiberauth

import (
	"testing"
	"time"
)

func TestTicket_IssueConsume(t *testing.T) {
	ts := NewTicketStore(time.Minute)
	tok, err := ts.Issue("uid1", "folder/a")
	if err != nil {
		t.Fatal(err)
	}
	uid, scope, ok := ts.Consume(tok)
	if !ok || uid != "uid1" || scope != "folder/a" {
		t.Fatalf("consume: got %q %q %v", uid, scope, ok)
	}
}

func TestTicket_SingleUse(t *testing.T) {
	ts := NewTicketStore(time.Minute)
	tok, _ := ts.Issue("uid1", "x")
	ts.Consume(tok)
	if _, _, ok := ts.Consume(tok); ok {
		t.Fatal("replay within TTL must fail")
	}
}

func TestTicket_UnknownAndEmpty(t *testing.T) {
	ts := NewTicketStore(time.Minute)
	if _, _, ok := ts.Consume("nope"); ok {
		t.Fatal("unknown ticket accepted")
	}
	if _, _, ok := ts.Consume(""); ok {
		t.Fatal("empty ticket accepted")
	}
}

func TestTicket_Expired(t *testing.T) {
	ts := NewTicketStore(time.Millisecond)
	tok, _ := ts.Issue("uid1", "x")
	time.Sleep(5 * time.Millisecond)
	if _, _, ok := ts.Consume(tok); ok {
		t.Fatal("expired ticket accepted")
	}
}
