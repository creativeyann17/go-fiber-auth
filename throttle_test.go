package fiberauth

import (
	"testing"
	"time"
)

func newTestThrottle() *Throttle { return NewThrottle(15*time.Minute, time.Hour) }

func TestThrottle_LocksAtThreshold(t *testing.T) {
	tr := newTestThrottle()
	const max = 3
	for i := range max - 1 {
		tr.Fail("k", max)
		if locked, _ := tr.Locked("k"); locked {
			t.Fatalf("locked too early at attempt %d", i+1)
		}
	}
	tr.Fail("k", max) // hits threshold
	locked, retry := tr.Locked("k")
	if !locked {
		t.Fatal("want locked after reaching threshold")
	}
	if retry <= 0 {
		t.Fatalf("want positive retry-after, got %v", retry)
	}
}

func TestThrottle_ResetClears(t *testing.T) {
	tr := newTestThrottle()
	tr.Fail("k", 3)
	tr.Fail("k", 3)
	tr.Reset("k")
	if locked, _ := tr.Locked("k"); locked {
		t.Fatal("reset should clear lock state")
	}
	// Counter restarts from zero: one more fail must not lock (threshold 3).
	tr.Fail("k", 3)
	if locked, _ := tr.Locked("k"); locked {
		t.Fatal("counter should have restarted after reset")
	}
}

func TestThrottle_KeysAreIndependent(t *testing.T) {
	tr := newTestThrottle()
	for range 5 {
		tr.Fail("login:alice", 5)
	}
	if locked, _ := tr.Locked("login:alice"); !locked {
		t.Fatal("alice should be locked")
	}
	if locked, _ := tr.Locked("login:bob"); locked {
		t.Fatal("bob must not be affected by alice's failures")
	}
}

func TestThrottle_PruneDropsStaleEntries(t *testing.T) {
	tr := NewThrottle(15*time.Minute, 10*time.Millisecond)
	tr.Fail("k", 100) // single fail, never locked
	time.Sleep(20 * time.Millisecond)
	// Force a prune via a fail on a different key past the ttl window.
	tr.mu.Lock()
	tr.lastPrune = time.Now().Add(-time.Hour)
	tr.mu.Unlock()
	tr.Fail("other", 100)
	tr.mu.Lock()
	_, present := tr.byKey["k"]
	tr.mu.Unlock()
	if present {
		t.Fatal("stale entry should have been pruned")
	}
}

func TestLoginThrottle_PerLoginLock(t *testing.T) {
	lt := NewLoginThrottle(LoginThrottleConfig{LoginMaxFails: 3})
	for range 3 {
		lt.Fail("alice", "1.2.3.4")
	}
	if locked, _ := lt.Locked("alice", "5.6.7.8"); !locked {
		t.Fatal("alice must be locked regardless of IP")
	}
	if locked, _ := lt.Locked("bob", "5.6.7.8"); locked {
		t.Fatal("bob must not be locked")
	}
}

func TestLoginThrottle_PerIPLock(t *testing.T) {
	lt := NewLoginThrottle(LoginThrottleConfig{LoginMaxFails: 100, IPMaxFails: 4})
	// Spray: many logins from one IP.
	for _, name := range []string{"a", "b", "c", "d"} {
		lt.Fail(name, "9.9.9.9")
	}
	if locked, _ := lt.Locked("fresh-login", "9.9.9.9"); !locked {
		t.Fatal("IP must be locked after spraying many logins")
	}
	if locked, _ := lt.Locked("fresh-login", "1.1.1.1"); locked {
		t.Fatal("other IPs must not be locked")
	}
}

func TestLoginThrottle_UnknownIPSkipsIPDimension(t *testing.T) {
	lt := NewLoginThrottle(LoginThrottleConfig{LoginMaxFails: 100, IPMaxFails: 2})
	lt.Fail("a", "unknown")
	lt.Fail("b", "unknown")
	lt.Fail("c", "")
	if locked, _ := lt.Locked("fresh", "unknown"); locked {
		t.Fatal(`"unknown" callers must not share one IP bucket`)
	}
}

func TestLoginThrottle_SucceededClearsLoginOnly(t *testing.T) {
	lt := NewLoginThrottle(LoginThrottleConfig{LoginMaxFails: 3, IPMaxFails: 3})
	lt.Fail("alice", "1.2.3.4")
	lt.Fail("alice", "1.2.3.4")
	lt.Succeeded("alice")
	// Per-login counter restarted: two more fails must not lock (threshold 3).
	lt.Fail("alice", "5.5.5.5")
	lt.Fail("alice", "5.5.5.5")
	if locked, _ := lt.Locked("alice", "5.5.5.5"); locked {
		t.Fatal("per-login counter should have restarted after Succeeded")
	}
	// But the original IP kept its 2 fails: one more trips it (threshold 3).
	lt.Fail("someone-else", "1.2.3.4")
	if locked, _ := lt.Locked("whoever", "1.2.3.4"); !locked {
		t.Fatal("per-IP counter must survive Succeeded")
	}
}

func TestLoginThrottle_FailReturnsPerLoginCount(t *testing.T) {
	lt := NewLoginThrottle(LoginThrottleConfig{})
	if got := lt.Fail("alice", "1.2.3.4"); got != 1 {
		t.Fatalf("first fail count: got %d want 1", got)
	}
	if got := lt.Fail("alice", "1.2.3.4"); got != 2 {
		t.Fatalf("second fail count: got %d want 2", got)
	}
}
