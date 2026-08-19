package swarmsync

import (
	"bytes"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/transfer"
)

func traceHas(events []transfer.HopEvent, role string) bool {
	for _, e := range events {
		if e.Role == role {
			return true
		}
	}
	return false
}

// TestObservabilityHopTraceAndPeerHealth runs a forwarded transfer with hop
// tracing enabled and asserts each node's local trace reflects its role (sender
// sent, a relay received+forwarded, destination delivered) and that peer-table
// health reports discovered, active peers.
func TestObservabilityHopTraceAndPeerHealth(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	payload := []byte("observability-over-the-swarm")

	recv := make(chan []byte, 4)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, TraceHops: true, OnDataReceived: func(b []byte) { recv <- b }})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true, TraceHops: true})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true, TraceHops: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1, Redundancy: 2, TraceHops: true})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	deliverBytesWithin(t, nodes, func() error { return sender.SendTo(payload, dest.NodeID()) }, recv, payload, 20*time.Second)

	// Give the destination's async deliver hook a moment to record its event.
	time.Sleep(200 * time.Millisecond)

	if !traceHas(sender.HopTrace(), transfer.HopSend) {
		t.Error("sender trace should contain a send event")
	}
	if !traceHas(dest.HopTrace(), transfer.HopDeliver) {
		t.Error("destination trace should contain a deliver event")
	}
	// At least one relay should have received and forwarded a hop.
	relayForwarded := false
	for _, r := range []*SyncSwarm{r1, r2} {
		tr := r.HopTrace()
		if traceHas(tr, transfer.HopReceive) && traceHas(tr, transfer.HopForward) {
			relayForwarded = true
		}
	}
	if !relayForwarded {
		t.Error("at least one relay should show receive + forward events")
	}

	// Peer-table health: the sender discovered the others and sees active peers.
	h := sender.PeerHealth()
	if h.Total == 0 || h.Active == 0 {
		t.Errorf("sender PeerHealth Total/Active = %d/%d, want > 0", h.Total, h.Active)
	}
	if h.PerSubnet == nil {
		t.Error("PeerHealth PerSubnet map should be populated")
	}

	// Aggregate counters advanced.
	if sender.Stats().FragmentsSent == 0 {
		t.Error("sender FragmentsSent counter did not advance")
	}
}
