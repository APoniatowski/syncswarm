package swarmsync

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"testing"
	"time"
)

// newTestNode creates a SyncSwarm on ephemeral loopback ports with a temp store.
func newTestNode(t *testing.T, opts Options) *SyncSwarm {
	t.Helper()
	if opts.StorageDir == "" {
		opts.StorageDir = t.TempDir()
	}
	opts.DiscoveryPort = -1
	opts.DataPort = -1
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New(%s): %v", opts.NodeID, err)
	}
	return s
}

// wireAndStart cross-wires every node's bootstrap list to all others and starts
// them, registering cleanup. It skips the test if ephemeral ports couldn't bind.
func wireAndStart(t *testing.T, nodes ...*SyncSwarm) {
	t.Helper()
	for _, n := range nodes {
		if n.DiscoveryPort() == 0 || n.DataPort() == 0 {
			t.Skip("could not bind ephemeral ports in this environment")
		}
	}
	for _, n := range nodes {
		var peers []string
		for _, m := range nodes {
			if m != n {
				peers = append(peers, fmt.Sprintf("127.0.0.1:%d", m.DiscoveryPort()))
			}
		}
		n.SetBootstrapPeers(peers)
	}
	for _, n := range nodes {
		if err := n.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() { n.Stop() })
	}
}

// deliverBytesWithin retries send (re-bootstrapping each round) until recv yields
// the wanted bytes or the deadline passes.
func deliverBytesWithin(t *testing.T, nodes []*SyncSwarm, send func() error, recv <-chan []byte, want []byte, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(200 * time.Millisecond)
		if err := send(); err != nil {
			continue
		}
		select {
		case got := <-recv:
			if !bytes.Equal(got, want) {
				t.Fatalf("delivered %d bytes, want %d", len(got), len(want))
			}
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatal("timed out waiting for end-to-end delivery")
}

// TestMultiNodeForwardedDelivery brings up four real nodes on ephemeral ports on
// loopback — a sender, a destination, and two relays — wires them together via
// bootstrap discovery, and sends a developer-key-sealed payload from the sender
// to the destination through the swarm. It asserts the destination receives the
// exact bytes. With HopCount=1 and Redundancy=2 the sender routes each fragment
// through a relay over two independent paths; if relays are not yet known it
// falls back to a direct send, so this test verifies real end-to-end delivery
// over sockets, discovery, ephemeral ports, and per-fragment sealing.
func TestMultiNodeForwardedDelivery(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	payload := []byte("the-emperor-protects: fragments spread across relays, reassembled only at the destination")

	recv := make(chan []byte, 4)

	mk := func(id string, relay bool, hop, redundancy int, onData func([]byte)) *SyncSwarm {
		s, err := New(Options{
			NodeID:             id,
			StorageDir:         t.TempDir(),
			Key:                key,
			DiscoveryPort:      -1, // ephemeral
			DataPort:           -1, // ephemeral
			Relay:              relay,
			HopCount:           hop,
			Redundancy:         redundancy,
			OnDataReceived:     onData,
			OnVariableReceived: func(interface{}) {},
		})
		if err != nil {
			t.Fatalf("New(%s): %v", id, err)
		}
		return s
	}

	dest := mk("dest", true, 0, 0, func(b []byte) { recv <- b })
	relay1 := mk("relay1", true, 0, 0, nil)
	relay2 := mk("relay2", true, 0, 0, nil)
	sender := mk("sender", false, 1, 2, nil)

	nodes := []*SyncSwarm{dest, relay1, relay2, sender}

	// Skip cleanly if the environment cannot bind loopback UDP/TCP at all.
	for _, n := range nodes {
		if n.DiscoveryPort() == 0 || n.DataPort() == 0 {
			t.Skip("could not bind ephemeral ports in this environment")
		}
	}

	// Wire every node's bootstrap list to every other node's discovery address.
	discAddr := func(n *SyncSwarm) string { return fmt.Sprintf("127.0.0.1:%d", n.DiscoveryPort()) }
	for _, n := range nodes {
		var peers []string
		for _, m := range nodes {
			if m != n {
				peers = append(peers, discAddr(m))
			}
		}
		n.SetBootstrapPeers(peers)
	}

	for _, n := range nodes {
		if err := n.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer n.Stop()
	}

	// Drive mutual discovery and delivery. Bootstrapping every node makes each
	// announce to all others so the sender learns the destination and relays.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(200 * time.Millisecond)

		if err := sender.SendTo(payload, dest.NodeID()); err != nil {
			continue // destination not discovered yet
		}
		select {
		case got := <-recv:
			if !bytes.Equal(got, payload) {
				t.Fatalf("delivered %q, want %q", got, payload)
			}
			return // success
		case <-time.After(500 * time.Millisecond):
			// Not delivered on this attempt; keep converging and retry.
		}
	}
	t.Fatal("timed out waiting for end-to-end delivery")
}

// TestMultiNodeErasureCoded sends an erasure-coded (Reed-Solomon 4+2) payload
// from sender to dest through relays over real sockets, asserting exact delivery.
func TestMultiNodeErasureCoded(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	payload := bytes.Repeat([]byte("erasure-over-the-wire-"), 2000) // ~44KB, many shards

	recv := make(chan []byte, 4)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnDataReceived: func(b []byte) { recv <- b }})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	deliverBytesWithin(t, nodes, func() error { return sender.SendTo(payload, dest.NodeID()) }, recv, payload, 20*time.Second)
}

// TestMultiNodeSubChunkedDelivery forces each Reed-Solomon shard to be split
// into several transport sub-chunks (SubChunkSize well below the shard size) and
// verifies the payload still reassembles exactly at the destination over the
// forwarded, onion-wrapped path — exercising sub-chunk fan-out and receiver-side
// sub-chunk reassembly before RS reconstruction (10.3).
func TestMultiNodeSubChunkedDelivery(t *testing.T) {
	key := bytes.Repeat([]byte{0x3c}, 32)
	payload := bytes.Repeat([]byte("sub-chunked-shards-over-the-swarm-"), 3000) // ~99KB

	recv := make(chan []byte, 4)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnDataReceived: func(b []byte) { recv <- b }})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true})
	// Shards are ~25KB (4 data shards); a 4KB sub-chunk cap splits each into ~7
	// pieces, all of which must arrive and reassemble.
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2, SubChunkSize: 4096})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	deliverBytesWithin(t, nodes, func() error { return sender.SendTo(payload, dest.NodeID()) }, recv, payload, 20*time.Second)
}

type varPayload struct {
	N   int
	Msg string
}

// TestMultiNodeVariableDelivery sends a gob-encoded variable end-to-end and
// asserts it arrives via OnVariableReceived as the original concrete type.
func TestMultiNodeVariableDelivery(t *testing.T) {
	gob.Register(varPayload{})
	key := bytes.Repeat([]byte{0x22}, 32)
	want := varPayload{N: 42, Msg: "for-the-emperor"}

	recv := make(chan varPayload, 4)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnVariableReceived: func(v interface{}) {
		if p, ok := v.(varPayload); ok {
			recv <- p
		}
	}})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(200 * time.Millisecond)
		if err := sender.SendVariableTo(want, dest.NodeID()); err != nil {
			continue
		}
		select {
		case got := <-recv:
			if got != want {
				t.Fatalf("delivered %+v, want %+v", got, want)
			}
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatal("timed out waiting for variable delivery")
}

// TestMultiNodeConfirmedDelivery exercises the full reliable stack: erasure
// coding + forwarding + redundancy + end-to-end acknowledgement. With
// ConfirmDelivery set, SendTo returns nil only once the destination's ack routes
// back to the sender.
func TestMultiNodeConfirmedDelivery(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	payload := bytes.Repeat([]byte("confirmed-and-reliable-"), 1500)

	recv := make(chan []byte, 8)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnDataReceived: func(b []byte) { recv <- b }})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2, ConfirmDelivery: true})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(300 * time.Millisecond)
		// With ConfirmDelivery, a nil return means the ack was received.
		if err := sender.SendTo(payload, dest.NodeID()); err != nil {
			continue
		}
		select {
		case got := <-recv:
			if !bytes.Equal(got, payload) {
				t.Fatalf("confirmed delivery mismatch: %d vs %d bytes", len(got), len(payload))
			}
			return
		case <-time.After(1 * time.Second):
			t.Fatal("SendTo confirmed but payload not delivered")
		}
	}
	t.Fatal("timed out waiting for confirmed delivery")
}

// TestMultiNodeCircuitRelay brings up a relay, a NAT'd destination that can only
// be reached via a circuit reservation, and a sender. The destination holds a
// persistent reservation with the relay and advertises it; the sender routes
// through that relay, which forwards over the held connection.
func TestMultiNodeCircuitRelay(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 32)
	payload := []byte("delivered-through-a-circuit-relay-behind-nat")

	recv := make(chan []byte, 4)
	relay := newTestNode(t, Options{NodeID: "relay", Key: key, Relay: true})
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, NeedsRelay: true, OnDataReceived: func(b []byte) { recv <- b }})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1})

	nodes := []*SyncSwarm{relay, dest, sender}
	wireAndStart(t, nodes...)

	// The destination needs time to discover the relay, establish its reservation,
	// and advertise it before the sender can route through it.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(300 * time.Millisecond)
		if err := sender.SendTo(payload, dest.NodeID()); err != nil {
			continue
		}
		select {
		case got := <-recv:
			if !bytes.Equal(got, payload) {
				t.Fatalf("delivered %q, want %q", got, payload)
			}
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatal("timed out waiting for delivery to a circuit-reserved destination")
}

// TestMultiNodeAnonymityHardening enables cover traffic, padding, and relay
// jitter, and asserts real delivery still works through the noise.
func TestMultiNodeAnonymityHardening(t *testing.T) {
	key := bytes.Repeat([]byte{0x66}, 32)
	payload := bytes.Repeat([]byte("hardened-anonymous-transfer-"), 50)

	recv := make(chan []byte, 4)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnDataReceived: func(b []byte) { recv <- b }})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true, RelayJitter: 15 * time.Millisecond})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true, RelayJitter: 15 * time.Millisecond})
	sender := newTestNode(t, Options{
		NodeID: "sender", Key: key, HopCount: 1, Redundancy: 2,
		CoverTraffic: true, PadCellSize: 1024, RelayJitter: 15 * time.Millisecond,
	})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	deliverBytesWithin(t, nodes, func() error { return sender.SendTo(payload, dest.NodeID()) }, recv, payload, 20*time.Second)
}
