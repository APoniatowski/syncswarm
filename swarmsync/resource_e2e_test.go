package swarmsync

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestSendToResource delivers a large multi-part payload reliably over a Link
// between two SDK nodes, verifying the Phase 0b.2 Resource-over-Link path
// end-to-end (segmentation, windowing, selective-ACK, in-order reassembly).
func TestSendToResource(t *testing.T) {
	got := make(chan []byte, 1)
	b := newTestNode(t, Options{NodeID: "b", OnDataReceived: func(d []byte) { got <- d }})
	a := newTestNode(t, Options{NodeID: "a"})
	nodes := []*SyncSwarm{a, b}
	wireAndStart(t, nodes...)

	payload := bytes.Repeat([]byte("reliable-link-transfer. "), 8000) // ~192 KB, many parts
	deliverBytesWithin(t, nodes, func() error {
		return a.SendToResource(b.NodeID(), payload)
	}, got, payload, 20*time.Second)
}

// TestReliableLinkTransfer_Flag verifies Options.ReliableLinkTransfer routes the
// ordinary SendTo through the Resource-over-Link path.
func TestReliableLinkTransfer_Flag(t *testing.T) {
	got := make(chan []byte, 1)
	b := newTestNode(t, Options{NodeID: "b", OnDataReceived: func(d []byte) { got <- d }})
	a := newTestNode(t, Options{NodeID: "a", ReliableLinkTransfer: true})
	nodes := []*SyncSwarm{a, b}
	wireAndStart(t, nodes...)

	payload := []byte("delivered via SendTo with ReliableLinkTransfer")
	deliverBytesWithin(t, nodes, func() error {
		return a.SendTo(payload, b.NodeID())
	}, got, payload, 20*time.Second)
}

// TestSendToResource_AcrossBridge proves a reliable transfer crosses a TCP bridge:
// the two nodes are on distinct ephemeral discovery ports (separate broadcast
// domains) and are NOT cross-bootstrapped — they find each other only through the
// bridge, and the resource rides it too (unicast-over-bridge).
func TestSendToResource_AcrossBridge(t *testing.T) {
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))

	got := make(chan []byte, 1)
	b := newTestNode(t, Options{NodeID: "b", BridgeListen: addr, OnDataReceived: func(d []byte) { got <- d }})
	a := newTestNode(t, Options{NodeID: "a", BridgePeers: []string{addr}})
	for _, n := range []*SyncSwarm{a, b} {
		if n.DiscoveryPort() == 0 || n.DataPort() == 0 {
			t.Skip("could not bind ephemeral ports in this environment")
		}
	}
	// Start without cross-bootstrapping: the only path between them is the bridge.
	for _, n := range []*SyncSwarm{b, a} {
		if err := n.Start(); err != nil {
			t.Fatalf("Start(%s): %v", n.NodeID(), err)
		}
		t.Cleanup(func() { n.Stop() })
	}

	payload := bytes.Repeat([]byte("across-the-bridge. "), 3000) // ~57 KB
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		if err := a.SendToResource(b.NodeID(), payload); err != nil {
			continue // not discovered over the bridge yet
		}
		select {
		case d := <-got:
			if !bytes.Equal(d, payload) {
				t.Fatalf("across bridge: got %d bytes, want %d", len(d), len(payload))
			}
			return
		case <-time.After(1 * time.Second):
		}
	}
	t.Fatal("timed out waiting for reliable delivery across the bridge")
}

// freePort returns a currently-free TCP port on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot allocate a port in this environment")
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
