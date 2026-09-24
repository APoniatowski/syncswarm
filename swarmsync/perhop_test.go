package swarmsync

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestPerHopRouting delivers a targeted transfer with PerHopRouting enabled and
// proves the routed path was actually exercised — not merely a direct fallback —
// by finding a "routed" hop in the sender's trace. The two nodes are connected
// only by a TCP bridge, so announces cross it and populate the path table that
// per-hop routing consults (the unicast-bootstrap test topology never floods
// announces, so it would leave the path table empty).
func TestPerHopRouting(t *testing.T) {
	payload := []byte("delivered via per-hop transport routing")

	var mu sync.Mutex
	delivered := false
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	b := newTestNode(t, Options{NodeID: "b", BridgeListen: addr, OnDataReceived: func(d []byte) {
		if bytes.Equal(d, payload) {
			mu.Lock()
			delivered = true
			mu.Unlock()
		}
	}})
	a := newTestNode(t, Options{NodeID: "a", BridgePeers: []string{addr}, PerHopRouting: true, TraceHops: true, TraceSize: 256})
	for _, n := range []*SyncSwarm{a, b} {
		if n.DiscoveryPort() == 0 || n.DataPort() == 0 {
			t.Skip("could not bind ephemeral ports in this environment")
		}
		if err := n.Start(); err != nil {
			t.Fatalf("Start(%s): %v", n.NodeID(), err)
		}
		t.Cleanup(func() { n.Stop() })
	}

	routed := false
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) && !routed {
		time.Sleep(300 * time.Millisecond)
		_ = a.SendTo(payload, b.NodeID())
		for _, e := range a.HopTrace() {
			if e.Detail == "routed" {
				routed = true
			}
		}
	}
	if !routed {
		t.Fatal("per-hop routing was never exercised (no routed hop in the sender trace)")
	}

	ok := false
	for i := 0; i < 30 && !ok; i++ {
		mu.Lock()
		ok = delivered
		mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	if !ok {
		t.Fatal("routed transfer did not deliver to the destination")
	}
}

// TestPerHopRouting_ConfirmDelivery proves ConfirmDelivery works over the routed
// path: the destination routes a signed delivery ack back through the path table,
// so a confirmed per-hop send returns nil (acknowledged) — and a routed hop is in
// the sender's trace, showing the routed path (not a direct fallback) carried it.
func TestPerHopRouting_ConfirmDelivery(t *testing.T) {
	payload := []byte("confirmed delivery over per-hop routing")
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	b := newTestNode(t, Options{NodeID: "b", BridgeListen: addr, OnDataReceived: func([]byte) {}})
	a := newTestNode(t, Options{NodeID: "a", BridgePeers: []string{addr},
		PerHopRouting: true, ConfirmDelivery: true, TraceHops: true, TraceSize: 256})
	for _, n := range []*SyncSwarm{a, b} {
		if n.DiscoveryPort() == 0 || n.DataPort() == 0 {
			t.Skip("could not bind ephemeral ports in this environment")
		}
		if err := n.Start(); err != nil {
			t.Fatalf("Start(%s): %v", n.NodeID(), err)
		}
		t.Cleanup(func() { n.Stop() })
	}

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		err := a.SendTo(payload, b.NodeID()) // blocks until acked or the ack budget is spent
		routed := false
		for _, e := range a.HopTrace() {
			if e.Detail == "routed" {
				routed = true
			}
		}
		if err == nil && routed {
			return // confirmed ack arrived back over the routed path
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("confirmed per-hop delivery never acked over the routed path")
}
