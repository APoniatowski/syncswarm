package link

import (
	"testing"
	"time"
)

// TestDialCached_ReusesLink verifies a second dial to the same peer returns the
// cached link (no new handshake), and that closing it evicts the cache so a later
// dial establishes a fresh session.
func TestDialCached_ReusesLink(t *testing.T) {
	a, b, bPub := pair(t)

	inbound := make(chan *Link, 8)
	b.OnInboundLink(func(l *Link) { inbound <- l })

	l1, err := a.DialCached("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-inbound:
	case <-time.After(2 * time.Second):
		t.Fatal("responder never saw the first link")
	}

	l2, err := a.DialCached("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if l1 != l2 {
		t.Fatal("DialCached did not reuse the cached link")
	}
	// No second inbound link should have been created for the reuse.
	select {
	case <-inbound:
		t.Fatal("reuse established a new session on the responder")
	case <-time.After(300 * time.Millisecond):
	}

	// Closing evicts; the next dial establishes a fresh link.
	l1.Close()
	l3, err := a.DialCached("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if l3 == l1 {
		t.Fatal("closed link was not evicted from the cache")
	}
}

// TestNewRouter_Idempotent ensures a reused link keeps a single Router (so its
// OnData handler isn't clobbered by a second caller wrapping the same link).
func TestNewRouter_Idempotent(t *testing.T) {
	a, b, bPub := pair(t)
	b.OnInboundLink(func(l *Link) {})

	l, err := a.DialCached("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if NewRouter(l) != NewRouter(l) {
		t.Fatal("NewRouter returned different Routers for the same link")
	}
}
