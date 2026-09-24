package discovery

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// TestLatency_RejectsReplyFromDifferentIdentity is the regression test for the
// "ghost peer" bug: liveness must prove the *identity* is still there, not merely
// that something answers at its address.
//
// A node whose identity changes (storage wiped, host re-provisioned) leaves a
// stale entry behind. Its successor answers at the same address, and because the
// latency reply was matched on nonce alone, the dead identity was marked active
// forever — and stayed eligible for onion paths, where layers get sealed to its
// advertised public key and become silently undeliverable.
//
// Here B is live, and A holds a ghost entry pointing at B's address under a
// different node ID. B's reply must NOT satisfy the ghost's liveness check.
func TestLatency_RejectsReplyFromDifferentIdentity(t *testing.T) {
	b, bid := realDiscovery(t, "relay")
	a, _ := realDiscovery(t)
	a.Start()
	defer a.Stop()
	b.Start()
	defer b.Stop()

	bAddr := fmt.Sprintf("127.0.0.1:%d", b.Port())

	// Sanity: a check against B's real identity succeeds, so the transport works
	// and any failure below is the identity binding, not a broken round trip.
	real := &Node{ID: bid, Address: bAddr, Active: true}
	if lat := a.measureLatency(real); lat >= maxLatency {
		t.Fatalf("latency to B's real identity = %v (>= maxLatency); transport is broken, test inconclusive", lat)
	}

	// The ghost: B's address, someone else's identity.
	ghost := &Node{
		ID:      "00000000000000000000000000000000",
		Address: bAddr,
		Active:  true,
	}
	lat := a.measureLatency(ghost)
	if lat < maxLatency {
		t.Fatalf("ghost identity at a live address measured %v (< maxLatency): a reply from a "+
			"different node satisfied its liveness check, so the stale entry would never expire", lat)
	}
}

// TestLatency_GhostGoesInactive checks the table-level consequence: a ghost entry
// fails its check and is marked inactive, so it ages out instead of being kept
// alive by its successor.
func TestLatency_GhostGoesInactive(t *testing.T) {
	b, _ := realDiscovery(t, "relay")
	a, _ := realDiscovery(t)
	a.Start()
	defer a.Stop()
	b.Start()
	defer b.Stop()

	ghostID := "11111111111111111111111111111111"
	a.mu.Lock()
	a.nodes[ghostID] = &Node{
		ID:       ghostID,
		Address:  fmt.Sprintf("127.0.0.1:%d", b.Port()),
		Active:   true,
		LastSeen: time.Now(),
	}
	a.mu.Unlock()

	a.mu.RLock()
	ghost := a.nodes[ghostID]
	a.mu.RUnlock()
	if lat := a.measureLatency(ghost); lat < maxLatency {
		t.Fatalf("ghost measured %v; expected it to time out", lat)
	}
}

// TestLearnContacts_DoesNotAssertLiveness covers the DHT vector of the same bug:
// FIND_NODE contacts are a third party's list, not evidence any of those nodes is
// alive. Admitting them active let every 30s DHT refresh re-activate peers the
// latency round had just demoted, so dead nodes oscillated in and out of the
// routing set indefinitely (observed live as active counts going 8 -> 16 -> 13).
// Key binding is still enforced by learnContacts; only liveness is withheld.
func TestLearnContacts_DoesNotAssertLiveness(t *testing.T) {
	d := newTestDiscovery("self")
	id, signKey := boundID(t)

	d.learnContacts([]protocol.DHTContact{{
		NodeID:  id,
		Address: "10.9.9.9:64512",
		SignKey: signKey,
		Port:    64513,
	}})

	node, ok := d.nodes[id]
	if !ok {
		t.Fatal("a key-bound DHT contact should still be learned as a candidate")
	}
	if node.Active {
		t.Error("a DHT contact is hearsay; it must not be admitted as an active peer")
	}
	if node.Address != "10.9.9.9:64512" {
		t.Errorf("Address = %q, want the contact's address", node.Address)
	}
}

// TestCheckLatencies_ProbesConcurrently guards the fix for a scalability defect:
// probes were sequential, and each unreachable peer costs a full maxLatency
// timeout, so a round scaled with the table (~17 minutes at maxPeers) and nothing
// got re-verified meanwhile. That became critical once a first-hand probe was the
// only route to Active.
//
// With unreachable peers, a sequential sweep would take n*maxLatency; the bounded
// pool should finish in roughly one timeout.
func TestCheckLatencies_ProbesConcurrently(t *testing.T) {
	// A real socket is needed: measureLatency sends on the interface, which the
	// socket-free test Discovery does not have.
	d, _ := realDiscovery(t)
	defer d.Stop()

	const n = 12
	for i := 0; i < n; i++ {
		id, signKey := boundID(t)
		// 192.0.2.0/24 is TEST-NET-1: reserved and routed nowhere, so every probe
		// runs to the full timeout.
		d.nodes[id] = &Node{
			ID:       id,
			Address:  fmt.Sprintf("192.0.2.%d:64512", i+1),
			SignKey:  signKey,
			Active:   true,
			LastSeen: time.Now(),
		}
	}

	start := time.Now()
	d.checkLatencies()
	elapsed := time.Since(start)

	sequential := n * maxLatency
	if elapsed >= sequential {
		t.Fatalf("checkLatencies took %v for %d unreachable peers; sequential would be %v — probes are not concurrent",
			elapsed, n, sequential)
	}
	// All of them failed to answer, so none may remain active.
	for id, node := range d.nodes {
		if node.Active {
			t.Errorf("peer %s stayed active despite never answering", id[:8])
		}
	}
	t.Logf("probed %d unreachable peers in %v (sequential would be %v)", n, elapsed.Round(time.Millisecond), sequential)
}

// TestAnnounce_ForwardedIsHearsay covers the last liveness vector. A re-flooded
// announce (HopCount > 0) is hearsay twice over: it is no evidence the origin is
// still alive, and the address it arrived from is the *forwarder's*, not the
// origin's. Recording that address would corrupt the origin's — and, combined
// with identity-bound liveness, would make the node permanently unverifiable,
// because probing the forwarder's address gets a reply signed by the forwarder.
// A direct announce (HopCount 0) is first-hand and still confers both.
func TestAnnounce_ForwardedIsHearsay(t *testing.T) {
	origin := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 64512}
	forwarder := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99), Port: 64512}

	t.Run("direct announce is first-hand", func(t *testing.T) {
		d := newTestDiscovery("self")
		priv, id := newIdentity(t)
		if !d.handleAnnounce(origin, nil, signedAnnounce(t, priv, id, 0, time.Now().UnixNano(), 1)) {
			t.Fatal("a direct announce should be accepted")
		}
		n := d.nodes[id]
		if n == nil {
			t.Fatal("origin should be learned")
		}
		if !n.Active {
			t.Error("a direct announce is first-hand contact; the node should be active")
		}
		if n.Address != origin.String() {
			t.Errorf("Address = %q, want the origin's %q", n.Address, origin.String())
		}
	})

	t.Run("forwarded announce confers neither liveness nor address", func(t *testing.T) {
		d := newTestDiscovery("self")
		priv, id := newIdentity(t)
		// Arrives via a transport node: 3 hops travelled, seen from the forwarder.
		if !d.handleAnnounce(forwarder, nil, signedAnnounce(t, priv, id, 3, time.Now().UnixNano(), 1)) {
			t.Fatal("a forwarded announce should still be accepted and learned")
		}
		n := d.nodes[id]
		if n == nil {
			t.Fatal("origin should still be learned as a candidate")
		}
		if n.Active {
			t.Error("a re-flooded announce is hearsay; it must not mark the origin active")
		}
	})

	t.Run("forwarded announce does not overwrite a known address", func(t *testing.T) {
		d := newTestDiscovery("self")
		priv, id := newIdentity(t)
		// Learn it directly first, then hear a re-flooded copy via a forwarder.
		d.handleAnnounce(origin, nil, signedAnnounce(t, priv, id, 0, time.Now().UnixNano(), 1))
		d.handleAnnounce(forwarder, nil, signedAnnounce(t, priv, id, 4, time.Now().UnixNano(), 2))

		if got := d.nodes[id].Address; got != origin.String() {
			t.Fatalf("Address = %q, want the origin's %q — a forwarder's address must not "+
				"replace it, or the node becomes permanently unverifiable", got, origin.String())
		}
	})
}

// TestUpdateNode_AnnounceDoesNotWipeRelayIDs is the regression test for the bug
// that broke NAT'd delivery outright.
//
// A node behind NAT holds circuit reservations and advertises them as RelayIDs, so
// senders know to route the final hop through a relay that can actually reach it.
// Those IDs travel in discovery packets — but AnnouncePayload has no RelayIDs
// field, so handleAnnounce passes nil, and RelayIDs was assigned unconditionally.
// Every announce therefore erased the reservation a discovery packet had just
// published, at roughly the same cadence it was published. Senders never saw a
// relay to route through, and delivery to any NAT'd peer silently failed.
//
// nil now means "this message carries no reservation info"; an explicit empty list
// still clears them.
func TestUpdateNode_AnnounceDoesNotWipeRelayIDs(t *testing.T) {
	d := newTestDiscovery("self")
	id, signKey := boundID(t)

	// A discovery packet advertises the peer's reservation relays.
	d.updateNode(id, "10.0.0.5:64512", []byte{9}, signKey, 64513, []string{"relay"}, []string{"relayA", "relayB"}, nil)
	if got := d.nodes[id].RelayIDs; len(got) != 2 {
		t.Fatalf("RelayIDs = %v, want the two advertised relays", got)
	}

	// An announce for the same peer carries no reservation information (nil).
	d.updateNode(id, "10.0.0.5:64512", []byte{9}, signKey, 64513, []string{"relay"}, nil, nil)
	if got := d.nodes[id].RelayIDs; len(got) != 2 {
		t.Fatalf("RelayIDs = %v after an announce; nil must mean 'no information', "+
			"not 'the peer has no reservations' — otherwise NAT'd peers become unreachable", got)
	}

	// An *empty* list must not erase them either. JSON round-trips make nil and []
	// indistinguishable in places, and gossip carrying an empty list was wiping a
	// reservation moments after it was advertised — observed live as relay_ids
	// flipping [relayA] -> [] within seconds. Stale IDs are harmless because
	// CircuitReachable requires the named relay to be verified and active.
	d.updateNode(id, "10.0.0.5:64512", []byte{9}, signKey, 64513, []string{"relay"}, []string{}, nil)
	if got := d.nodes[id].RelayIDs; len(got) != 2 {
		t.Fatalf("RelayIDs = %v after an empty list; only a non-empty list carries "+
			"reservation information", got)
	}

	// Gossip must not erase them either.
	d.mergePeer(protocol.PeerInfo{
		NodeID: id, SignKey: signKey, Address: "10.0.0.5:64512",
		LastSeen: time.Now().Add(time.Minute), RelayIDs: nil,
	}, false)
	if got := d.nodes[id].RelayIDs; len(got) != 2 {
		t.Fatalf("RelayIDs = %v after gossip with none; gossip must not erase a "+
			"reservation the peer advertised", got)
	}
}
