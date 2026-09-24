package link

import (
	"bytes"
	"testing"
	"time"
)

// TestRouter_RelaySubProtocol proves onion relay blobs ride their own channel and
// reassemble at the peer, without colliding with message/resource traffic.
func TestRouter_RelaySubProtocol(t *testing.T) {
	a, b, bPub := pair(t)

	relays := make(chan []byte, 4)
	b.OnInboundLink(func(l *Link) {
		NewRouter(l).OnRelay(func(blob []byte) { relays <- blob })
	})

	la, err := a.Dial("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	blob := bytes.Repeat([]byte("onion-blob-"), 4000) // multi-frame
	if err := NewRouter(la).SendRelay(blob); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-relays:
		if !bytes.Equal(got, blob) {
			t.Fatalf("relay blob = %d bytes, want %d", len(got), len(blob))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no relay blob delivered")
	}
}

// TestRouter_MessageAndResourceCoexist proves both sub-protocols share one Link
// without confusing each other: a best-effort message and a reliable resource sent
// over the same link both arrive intact at their respective handlers.
func TestRouter_MessageAndResourceCoexist(t *testing.T) {
	a, b, bPub := pair(t)

	msgs := make(chan []byte, 4)
	resources := make(chan []byte, 4)
	b.OnInboundLink(func(l *Link) {
		r := NewRouter(l)
		r.OnMessage(func(d []byte) { msgs <- d })
		r.OnResource(func(_ [16]byte, d []byte) { resources <- d })
	})

	la, err := a.Dial("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ra := NewRouter(la)

	// Best-effort message.
	if err := ra.SendMessage([]byte("a message")); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-msgs:
		if string(m) != "a message" {
			t.Fatalf("message = %q", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no message delivered")
	}

	// Reliable resource, multi-part.
	payload := bytes.Repeat([]byte("reliable-"), 5000) // ~45 KB
	go func() {
		if err := ra.SendResource(payload, 10*time.Second); err != nil {
			t.Errorf("SendResource: %v", err)
		}
	}()
	select {
	case r := <-resources:
		if !bytes.Equal(r, payload) {
			t.Fatalf("resource = %d bytes, want %d", len(r), len(payload))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no resource delivered")
	}
}
