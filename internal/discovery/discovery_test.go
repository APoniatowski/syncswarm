package discovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/iface"
	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// boundID returns a key-bound (NodeID, SignKey) pair, as mergePeer now requires.
func boundID(t *testing.T) (string, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.DeriveNodeID(pub), pub
}

// newTestDiscovery builds a Discovery with initialized maps but no open socket,
// so the pure (socket-free) helpers can be exercised without binding the fixed
// UDP discovery port.
func newTestDiscovery(selfID string) *Discovery {
	ctx, cancel := context.WithCancel(context.Background())
	return &Discovery{
		nodes:          make(map[string]*Node),
		selfID:         selfID,
		ctx:            ctx,
		cancel:         cancel,
		pending:        make(map[uint64]chan time.Time),
		observedCounts: make(map[string]int),
		paths:          newPathTable(maxPaths),
		seenAnn:        newDedupSet(announceDedupTTL),
		nodeIface:      make(map[string]iface.Interface),
		addrIface:      make(map[string]iface.Interface),
	}
}

func TestMergePeer_AddsNewPeer(t *testing.T) {
	d := newTestDiscovery("self")

	id, signKey := boundID(t)
	now := time.Now()
	pi := protocol.PeerInfo{
		NodeID:       id,
		Address:      "10.0.0.5:64512",
		PubKey:       []byte{1, 2, 3, 4},
		SignKey:      signKey,
		Port:         9000,
		Capabilities: []string{"relay"},
		LastSeen:     now,
	}

	d.mergePeer(pi)

	node, ok := d.nodes[id]
	if !ok {
		t.Fatalf("expected peer to be added to node table")
	}
	if node.Address != pi.Address {
		t.Errorf("Address = %q, want %q", node.Address, pi.Address)
	}
	if !bytes.Equal(node.PubKey, pi.PubKey) {
		t.Errorf("PubKey = %v, want %v", node.PubKey, pi.PubKey)
	}
	if node.Port != pi.Port {
		t.Errorf("Port = %d, want %d", node.Port, pi.Port)
	}
	if len(node.Capabilities) != 1 || node.Capabilities[0] != "relay" {
		t.Errorf("Capabilities = %v, want [relay]", node.Capabilities)
	}
	if !node.Active {
		t.Errorf("expected new peer to be Active")
	}
	if !node.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", node.LastSeen, now)
	}
}

func TestMergePeer_RefreshesLastSeen(t *testing.T) {
	d := newTestDiscovery("self")

	id, signKey := boundID(t)
	first := time.Now()
	d.mergePeer(protocol.PeerInfo{NodeID: id, SignKey: signKey, Address: "a:1", LastSeen: first})

	newer := first.Add(1 * time.Minute)
	d.mergePeer(protocol.PeerInfo{NodeID: id, SignKey: signKey, Address: "a:1", LastSeen: newer})

	node := d.nodes[id]
	if !node.LastSeen.Equal(newer) {
		t.Errorf("LastSeen = %v, want refreshed to %v", node.LastSeen, newer)
	}
}

func TestMergePeer_RejectsUnboundIdentity(t *testing.T) {
	d := newTestDiscovery("self")

	// NodeID that does not match DeriveNodeID(SignKey) must be rejected.
	_, signKey := boundID(t)
	d.mergePeer(protocol.PeerInfo{NodeID: "spoofed-id", SignKey: signKey, Address: "x:1", LastSeen: time.Now()})
	if _, ok := d.nodes["spoofed-id"]; ok {
		t.Fatal("mergePeer must reject a peer whose ID is not bound to its SignKey")
	}

	// Missing SignKey entirely is also rejected.
	d.mergePeer(protocol.PeerInfo{NodeID: "no-key", Address: "y:1", LastSeen: time.Now()})
	if _, ok := d.nodes["no-key"]; ok {
		t.Fatal("mergePeer must reject a peer with no SignKey")
	}
}

func TestMergePeer_SkipsSelf(t *testing.T) {
	d := newTestDiscovery("self")

	d.mergePeer(protocol.PeerInfo{NodeID: "self", Address: "x:1", LastSeen: time.Now()})

	if _, ok := d.nodes["self"]; ok {
		t.Errorf("mergePeer must not add the local node to the table")
	}
}

func TestMergePeer_DoesNotRegressNewerLastSeen(t *testing.T) {
	d := newTestDiscovery("self")

	id, signKey := boundID(t)
	newer := time.Now()
	d.mergePeer(protocol.PeerInfo{NodeID: id, SignKey: signKey, Address: "new:1", LastSeen: newer})

	older := newer.Add(-5 * time.Minute)
	d.mergePeer(protocol.PeerInfo{NodeID: id, SignKey: signKey, Address: "old:1", LastSeen: older})

	node := d.nodes[id]
	if !node.LastSeen.Equal(newer) {
		t.Errorf("LastSeen regressed to %v, want to keep newer %v", node.LastSeen, newer)
	}
	if node.Address != "new:1" {
		t.Errorf("Address = %q, staler merge must not overwrite it (want new:1)", node.Address)
	}
}

func TestBuildPeerExchangePayload(t *testing.T) {
	d := newTestDiscovery("self")
	d.SetIdentity([]byte{9, 9, 9}, 7777, []string{"relay", "store"})

	// One active, one inactive node.
	d.nodes["active"] = &Node{ID: "active", Address: "a:1", Active: true, Port: 100, LastSeen: time.Now()}
	d.nodes["down"] = &Node{ID: "down", Address: "d:1", Active: false, LastSeen: time.Now()}

	px := d.buildPeerExchangePayload()

	var selfPI *protocol.PeerInfo
	seen := map[string]bool{}
	for i := range px.Peers {
		p := &px.Peers[i]
		seen[p.NodeID] = true
		if p.NodeID == "self" {
			selfPI = p
		}
	}

	if selfPI == nil {
		t.Fatalf("expected self to be included in peer-exchange payload")
	}
	if !bytes.Equal(selfPI.PubKey, []byte{9, 9, 9}) {
		t.Errorf("self PubKey = %v, want [9 9 9]", selfPI.PubKey)
	}
	if selfPI.Port != 7777 {
		t.Errorf("self Port = %d, want 7777", selfPI.Port)
	}
	if len(selfPI.Capabilities) != 2 {
		t.Errorf("self Capabilities = %v, want 2 entries", selfPI.Capabilities)
	}
	if !seen["active"] {
		t.Errorf("expected active known node to be included")
	}
	if seen["down"] {
		t.Errorf("inactive node must not be included in gossip payload")
	}
}

func TestSettersStoreValues(t *testing.T) {
	d := newTestDiscovery("self")

	d.SetIdentity([]byte{1, 2}, 4242, []string{"relay"})
	d.SetBootstrapPeers([]string{"boot1:64512", "boot2:64512"})

	if !bytes.Equal(d.pubKey, []byte{1, 2}) {
		t.Errorf("pubKey = %v, want [1 2]", d.pubKey)
	}
	if d.port != 4242 {
		t.Errorf("port = %d, want 4242", d.port)
	}
	if len(d.capabilities) != 1 || d.capabilities[0] != "relay" {
		t.Errorf("capabilities = %v, want [relay]", d.capabilities)
	}
	if len(d.bootstrapPeers) != 2 {
		t.Errorf("bootstrapPeers = %v, want 2 entries", d.bootstrapPeers)
	}
}

// TestNewDiscoverySetters exercises the setters against a real NewDiscovery
// instance bound to an ephemeral port.
func TestNewDiscoverySetters(t *testing.T) {
	d, err := NewDiscovery("self", 0)
	if err != nil {
		t.Skipf("cannot bind discovery port in test environment: %v", err)
	}
	defer d.Stop()

	d.SetBootstrapPeers([]string{"boot:64512"})
	d.SetIdentity([]byte{7}, 555, []string{"relay"})

	if len(d.bootstrapPeers) != 1 || d.bootstrapPeers[0] != "boot:64512" {
		t.Errorf("bootstrapPeers = %v, want [boot:64512]", d.bootstrapPeers)
	}
	if d.port != 555 {
		t.Errorf("port = %d, want 555", d.port)
	}
}

func TestExternalHostObservation(t *testing.T) {
	d := newTestDiscovery("self")
	if d.ExternalHost() != "" {
		t.Fatal("no observations yet, external host should be empty")
	}
	// Two peers agree on one public host, one disagrees.
	d.recordObserved("203.0.113.7:40000")
	d.recordObserved("203.0.113.7:40001")
	d.recordObserved("198.51.100.9:5000")
	if got := d.ExternalHost(); got != "203.0.113.7" {
		t.Fatalf("ExternalHost = %q, want the majority-observed 203.0.113.7", got)
	}
	// Malformed observations are ignored.
	d.recordObserved("not-an-address")
}

func TestAntiEclipse_SubnetCap(t *testing.T) {
	d := newTestDiscovery("self") // no bootstrap configured

	// Flood 50 distinct Sybil identities all in one /24.
	for i := 1; i <= 50; i++ {
		id, sk := boundID(t)
		d.mergePeer(protocol.PeerInfo{NodeID: id, SignKey: sk, Address: fmt.Sprintf("10.0.0.%d:9000", i), LastSeen: time.Now()})
	}
	count := 0
	for _, n := range d.nodes {
		if subnetKey(n.Address) == subnetKey("10.0.0.1:0") {
			count++
		}
	}
	if count > maxPeersPerSubnet {
		t.Fatalf("subnet holds %d peers, want <= %d (Sybil flood not capped)", count, maxPeersPerSubnet)
	}

	// An honest peer in a distinct subnet still gets in.
	hid, hsk := boundID(t)
	d.mergePeer(protocol.PeerInfo{NodeID: hid, SignKey: hsk, Address: "203.0.113.5:9000", LastSeen: time.Now()})
	if _, ok := d.nodes[hid]; !ok {
		t.Fatal("honest peer in a distinct subnet must survive a same-subnet flood")
	}
}

func TestAntiEclipse_BootstrapProtected(t *testing.T) {
	d := newTestDiscovery("self")
	d.SetBootstrapPeers([]string{"10.0.0.1:64512"})

	// A bootstrap-host peer, deliberately stale.
	bid, bsk := boundID(t)
	d.mergePeer(protocol.PeerInfo{NodeID: bid, SignKey: bsk, Address: "10.0.0.1:64512", LastSeen: time.Now().Add(-time.Hour)})

	// Flood the same subnet with fresher Sybils.
	for i := 2; i < 60; i++ {
		id, sk := boundID(t)
		d.mergePeer(protocol.PeerInfo{NodeID: id, SignKey: sk, Address: fmt.Sprintf("10.0.0.%d:9000", i), LastSeen: time.Now()})
	}
	if _, ok := d.nodes[bid]; !ok {
		t.Fatal("bootstrap trust anchor must never be evicted by a Sybil flood")
	}
}

// TestPeerHealthComposition adds peers across subnets, deactivates one, and
// verifies PeerHealth reports the right active/inactive/subnet breakdown and
// that the join churn counter tracked the additions.
func TestPeerHealthComposition(t *testing.T) {
	d := newTestDiscovery("self")

	add := func(addr string) string {
		id, signKey := boundID(t)
		d.mergePeer(protocol.PeerInfo{
			NodeID:   id,
			Address:  addr,
			PubKey:   []byte{9},
			SignKey:  signKey,
			Port:     9000,
			LastSeen: time.Now(),
		})
		return id
	}

	add("10.0.0.1:64512")             // subnet 10.0.0.0/24
	add("10.0.0.2:64512")             // subnet 10.0.0.0/24
	inactive := add("10.0.1.9:64512") // subnet 10.0.1.0/24
	d.nodes[inactive].Active = false

	h := d.PeerHealth()
	if h.Total != 3 {
		t.Fatalf("Total = %d, want 3", h.Total)
	}
	if h.Active != 2 || h.Inactive != 1 {
		t.Fatalf("Active/Inactive = %d/%d, want 2/1", h.Active, h.Inactive)
	}
	if h.Subnets != 2 {
		t.Fatalf("Subnets = %d, want 2", h.Subnets)
	}
	if h.PerSubnet[subnetKey("10.0.0.1:64512")] != 2 {
		t.Fatalf("per-subnet count for 10.0.0.0/24 = %d, want 2", h.PerSubnet[subnetKey("10.0.0.1:64512")])
	}
	if h.Joins != 3 {
		t.Fatalf("Joins = %d, want 3", h.Joins)
	}
}
