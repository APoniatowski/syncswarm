package swarmsync

import (
	"bytes"
	"testing"
	"time"
)

// TestSendToLink delivers data end-to-end over an encrypted Link between two SDK
// nodes: A discovers B, dials a forward-secret session, and B receives the bytes
// via OnDataReceived — no shared key, erasure coding, or onion routing involved.
func TestSendToLink(t *testing.T) {
	got := make(chan []byte, 1)
	b := newTestNode(t, Options{NodeID: "b", OnDataReceived: func(d []byte) { got <- d }})
	a := newTestNode(t, Options{NodeID: "a"})

	nodes := []*SyncSwarm{a, b}
	wireAndStart(t, nodes...)

	payload := []byte("confidential over an encrypted link")

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(200 * time.Millisecond)
		// SendToLink fails until A has discovered B; keep trying until it does.
		if err := a.SendToLink(b.NodeID(), payload); err != nil {
			continue
		}
		select {
		case d := <-got:
			if !bytes.Equal(d, payload) {
				t.Fatalf("received %q, want %q", d, payload)
			}
			return
		case <-time.After(1 * time.Second):
		}
	}
	t.Fatal("timed out waiting for link delivery")
}
