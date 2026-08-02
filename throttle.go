package fiberauth

import (
	"sync"
	"time"
)

// Throttle is an in-memory keyed lockout. Generic core: callers pick the
// key namespace ("login:<name>", "ip:<addr>", "uid:<id>", ...) and the
// per-key threshold. No database: the map lives for the process
// lifetime. Stale entries are swept lazily so the map stays bounded even
// under a spray of random keys.
type Throttle struct {
	mu        sync.Mutex
	byKey     map[string]*attempt
	lockFor   time.Duration // lockout duration once tripped
	ttl       time.Duration // idle entries older than this are pruned
	lastPrune time.Time
}

type attempt struct {
	fails     int
	lockUntil time.Time
	seen      time.Time
}

func NewThrottle(lockFor, ttl time.Duration) *Throttle {
	return &Throttle{
		byKey:   make(map[string]*attempt),
		lockFor: lockFor,
		ttl:     ttl,
	}
}

// Locked reports whether key is currently locked out and, if so, how
// long until it may try again.
func (t *Throttle) Locked(key string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a := t.byKey[key]
	if a == nil {
		return false, 0
	}
	if d := time.Until(a.lockUntil); d > 0 {
		return true, d
	}
	return false, 0
}

// Fail records a failed attempt for key and returns the running count.
// Once the count reaches maxFails the key is locked for lockFor.
func (t *Throttle) Fail(key string, maxFails int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.pruneLocked(now)
	a := t.byKey[key]
	if a == nil {
		a = &attempt{}
		t.byKey[key] = a
	}
	a.fails++
	a.seen = now
	if a.fails >= maxFails {
		a.lockUntil = now.Add(t.lockFor)
	}
	return a.fails
}

// Reset clears any failure state for key (called on successful auth).
func (t *Throttle) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byKey, key)
}

// pruneLocked drops entries idle longer than ttl. Caller holds the lock.
// Runs at most once per ttl to keep the common path cheap.
func (t *Throttle) pruneLocked(now time.Time) {
	if now.Sub(t.lastPrune) < t.ttl {
		return
	}
	t.lastPrune = now
	for k, a := range t.byKey {
		if now.Sub(a.seen) > t.ttl && now.After(a.lockUntil) {
			delete(t.byKey, k)
		}
	}
}

// LoginThrottle wraps Throttle with two independent dimensions, each its
// own namespaced key:
//
//   - per-login ("login:<name>"): blunts a targeted brute-force against
//     one account. Includes unknown logins, so hammering a guessed
//     username is throttled too.
//   - per-IP ("ip:<addr>"): blunts a password-spray that walks many
//     usernames from one source. Higher threshold since several real
//     users may legitimately share an IP (NAT/office).
//
// A login is locked if *either* dimension is tripped. Both wrong-password
// and wrong-TOTP attempts count as a failure.
type LoginThrottle struct {
	t             *Throttle
	loginMaxFails int
	ipMaxFails    int
}

type LoginThrottleConfig struct {
	LockFor       time.Duration // lockout duration once tripped (default 15m)
	TTL           time.Duration // idle entries pruned after this (default 1h)
	LoginMaxFails int           // per-account threshold (default 5)
	IPMaxFails    int           // per-IP threshold, higher: shared NATs (default 20)
}

func NewLoginThrottle(cfg LoginThrottleConfig) *LoginThrottle {
	if cfg.LockFor == 0 {
		cfg.LockFor = 15 * time.Minute
	}
	if cfg.TTL == 0 {
		cfg.TTL = 1 * time.Hour
	}
	if cfg.LoginMaxFails == 0 {
		cfg.LoginMaxFails = 5
	}
	if cfg.IPMaxFails == 0 {
		cfg.IPMaxFails = 20
	}
	return &LoginThrottle{
		t:             NewThrottle(cfg.LockFor, cfg.TTL),
		loginMaxFails: cfg.LoginMaxFails,
		ipMaxFails:    cfg.IPMaxFails,
	}
}

// usableIP reports whether ip is concrete enough to throttle on. The
// ClientIP helper returns "unknown" when no address is resolvable; we
// don't want every such caller sharing one bucket.
func usableIP(ip string) bool { return ip != "" && ip != "unknown" }

// Locked reports whether either the login or the source IP is currently
// locked out, and the longest retry-after of the two.
func (l *LoginThrottle) Locked(login, ip string) (bool, time.Duration) {
	locked, retry := l.t.Locked("login:" + login)
	if usableIP(ip) {
		if lk, d := l.t.Locked("ip:" + ip); lk {
			locked = true
			if d > retry {
				retry = d
			}
		}
	}
	return locked, retry
}

// Fail records a failure against both dimensions and returns the running
// per-login count (used to pace failed-login admin email alerts).
func (l *LoginThrottle) Fail(login, ip string) int {
	count := l.t.Fail("login:"+login, l.loginMaxFails)
	if usableIP(ip) {
		l.t.Fail("ip:"+ip, l.ipMaxFails)
	}
	return count
}

// Succeeded clears the per-login counter on a successful auth. The
// per-IP counter is intentionally left to age out via TTL so one valid
// credential among a spray can't immediately reset the IP's budget.
func (l *LoginThrottle) Succeeded(login string) {
	l.t.Reset("login:" + login)
}
