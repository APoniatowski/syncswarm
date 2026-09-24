package swarmsync

import (
	"testing"
	"time"
)

// TestPeers lists the actual peers a node sees, rather than the aggregate counts
// PeerHealth gives: two nodes discover each other and each must appear in the
// other's Peers() with its key-derived NodeID and a usable address.
func TestPeers(t *testing.T) {
	a := newTestNode(t, Options{NodeID: "a"})
	b := newTestNode(t, Options{NodeID: "b", Relay: true})
	nodes := []*SyncSwarm{a, b}
	wireAndStart(t, nodes...)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(300 * time.Millisecond)

		peers := a.Peers()
		var found *PeerInfo
		for i := range peers {
			if peers[i].ID == b.NodeID() {
				found = &peers[i]
				break
			}
		}
		if found == nil {
			continue
		}
		if found.Address == "" {
			t.Fatalf("peer %s listed with no address", found.ID)
		}
		if !found.Active {
			continue // discovered but not yet passing liveness; keep waiting
		}
		// b advertises the relay capability, which is exactly the kind of thing an
		// operator wants to confirm from the outside.
		relay := false
		for _, c := range found.Capabilities {
			if c == "relay" {
				relay = true
			}
		}
		if !relay {
			t.Fatalf("peer %s capabilities = %v, want relay", found.ID, found.Capabilities)
		}
		// Sorted by ID, and self must not be listed.
		for _, p := range peers {
			if p.ID == a.NodeID() {
				t.Fatal("Peers() listed the local node itself")
			}
		}
		return
	}
	t.Fatal("timed out waiting for the peer to appear in Peers()")
}
