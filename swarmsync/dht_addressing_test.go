package swarmsync

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// TestTransparentDHTAddressing verifies that SendTo can reach a node the sender
// has only an ID for — never having discovered it directly — because the send
// path transparently resolves it via the DHT. A knows B; B knows C; A never
// bootstraps to C, and the test runs well inside the gossip interval, so the DHT
// lookup is the only way A can learn C.
func TestTransparentDHTAddressing(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 32)
	payload := []byte("reached-by-id-via-dht")
	recv := make(chan []byte, 4)

	a := newTestNode(t, Options{NodeID: "a", Key: key})                                                            // sender (direct send)
	b := newTestNode(t, Options{NodeID: "b", Key: key, Relay: true})                                               // bridge
	c := newTestNode(t, Options{NodeID: "c", Key: key, Relay: true, OnDataReceived: func(x []byte) { recv <- x }}) // dest
	all := []*SyncSwarm{a, b, c}
	for _, n := range all {
		if n.DiscoveryPort() == 0 || n.DataPort() == 0 {
			t.Skip("could not bind ephemeral ports in this environment")
		}
	}

	disc := func(n *SyncSwarm) string { return fmt.Sprintf("127.0.0.1:%d", n.DiscoveryPort()) }
	a.SetBootstrapPeers([]string{disc(b)})          // A learns B only
	b.SetBootstrapPeers([]string{disc(a), disc(c)}) // B learns A and C
	c.SetBootstrapPeers([]string{disc(b)})          // C learns B
	for _, n := range all {
		if err := n.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		t.Cleanup(func() { n.Stop() })
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		a.Bootstrap()
		b.Bootstrap()
		c.Bootstrap()
		time.Sleep(200 * time.Millisecond)

		// A addresses C purely by ID; if the routing tables aren't ready yet the
		// resolution (and thus the send) fails and we retry.
		if err := a.SendTo(payload, c.NodeID()); err != nil {
			continue
		}
		select {
		case got := <-recv:
			if !bytes.Equal(got, payload) {
				t.Fatalf("delivered %d bytes, want %d", len(got), len(payload))
			}
			return // success: reached C knowing only its ID
		case <-time.After(1 * time.Second):
		}
	}
	t.Fatal("timed out before ID-only delivery via DHT resolution")
}
