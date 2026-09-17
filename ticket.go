package fiberauth

import (
	"fmt"
	"sync"
	"time"
)

// TicketStore mints short-lived, single-use tickets that authorize one
// browser-navigation action (e.g. a streaming zip download). They exist
// so a plain navigation, which can't set an Authorization header, never
// carries the reusable session JWT in a URL where it would land in
// proxy/access logs.
//
// A ticket is an opaque random string bound to {uid, scope}. It is
// consumed (deleted) on first use and expires after ttl. In-memory,
// no DB.
type TicketStore struct {
	mu        sync.Mutex
	byTok     map[string]ticket
	ttl       time.Duration
	lastPrune time.Time
}

type ticket struct {
	uid     string
	scope   string
	expires time.Time
}

func NewTicketStore(ttl time.Duration) *TicketStore {
	return &TicketStore{byTok: make(map[string]ticket), ttl: ttl}
}

// Issue mints a ticket bound to uid+scope. The window is short because
// the client navigates to the target URL immediately after minting.
func (d *TicketStore) Issue(uid, scope string) (string, error) {
	tok, err := randomHex(32)
	if err != nil {
		return "", fmt.Errorf("generate ticket: %w", err)
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)
	d.byTok[tok] = ticket{uid: uid, scope: scope, expires: now.Add(d.ttl)}
	return tok, nil
}

// Consume validates a ticket and returns its bound identity. The ticket
// is deleted unconditionally on lookup (single-use), so a replay, even
// within the TTL, fails.
func (d *TicketStore) Consume(tok string) (uid, scope string, ok bool) {
	if tok == "" {
		return "", "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	t, found := d.byTok[tok]
	if !found {
		return "", "", false
	}
	delete(d.byTok, tok)
	if time.Now().After(t.expires) {
		return "", "", false
	}
	return t.uid, t.scope, true
}

// pruneLocked drops expired tickets. Caller holds the lock. Runs at most
// once per ttl so the common path stays cheap.
func (d *TicketStore) pruneLocked(now time.Time) {
	if now.Sub(d.lastPrune) < d.ttl {
		return
	}
	d.lastPrune = now
	for k, t := range d.byTok {
		if now.After(t.expires) {
			delete(d.byTok, k)
		}
	}
}
