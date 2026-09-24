package swarmsync

import (
	"bytes"
	"testing"
	"time"
)

// TestAdaptiveOnionFailsClosed verifies that AdaptiveOnionHops routes fail-closed:
// with no relays in the swarm there is zero relay diversity, so an anonymous send
// must error rather than degrade to a direct (sender-revealing) send.
func TestAdaptiveOnionFailsClosed(t *testing.T) {
	dest := newTestNode(t, Options{NodeID: "dest", OnDataReceived: func([]byte) {}})
	sender := newTestNode(t, Options{NodeID: "sender", AdaptiveOnionHops: true})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(200 * time.Millisecond)
		err := sender.SendTo([]byte("secret"), dest.NodeID())
		if err == nil {
			t.Fatal("adaptive send with no relays should fail closed, not send")
		}
		if bytes.Contains([]byte(err.Error()), []byte("no relay route")) {
			return // failed closed, as intended
		}
		// otherwise likely "not active" until discovery settles — keep trying
	}
	t.Fatal("timed out waiting for the destination to be discovered")
}
