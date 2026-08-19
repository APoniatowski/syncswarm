package transfer

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/discovery"
	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/routing"
)

// TestExcommunicationBookkeeping covers the "absolute after a couple of tries"
// rule: strikeLimit consecutive failures excommunicate a relay, a success
// absolves it, the excommunicated are excluded from routing, and the ban lifts
// (redemption) after the penance.
func TestExcommunicationBookkeeping(t *testing.T) {
	tr := &Transfer{
		strikeLimit:  3,
		penance:      time.Hour,
		relayStrikes: map[string]int{},
		excommunions: map[string]time.Time{},
	}

	// Two failures: not yet cast out.
	tr.recordProbe("r", false)
	tr.recordProbe("r", false)
	if tr.isExcommunicated("r") {
		t.Fatal("excommunicated before reaching the strike limit")
	}

	// A success absolves; the strike count resets.
	tr.recordProbe("r", true)
	tr.recordProbe("r", false)
	tr.recordProbe("r", false)
	if tr.isExcommunicated("r") {
		t.Fatal("a success should have reset the strikes")
	}

	// The third consecutive failure casts it out.
	tr.recordProbe("r", false)
	if !tr.isExcommunicated("r") {
		t.Fatal("should be excommunicated after 3 consecutive strikes")
	}

	// The excommunicated carry no traffic.
	nodes := []*discovery.Node{
		{ID: "r", PubKey: []byte{1}, Capabilities: []string{"relay"}, Active: true, Address: "1.1.1.1:1"},
		{ID: "good", PubKey: []byte{1}, Capabilities: []string{"relay"}, Active: true, Address: "2.2.2.2:1"},
	}
	got := tr.relayPeers(nodes, "")
	if len(got) != 1 || got[0].ID != "good" {
		t.Fatalf("relayPeers must exclude the excommunicated; got %v", ids(got))
	}

	// Redemption: once the penance has passed, the relay is eligible again.
	tr.excommunions["r"] = time.Now().Add(-time.Minute)
	if tr.isExcommunicated("r") {
		t.Fatal("an expired excommunication should be lifted")
	}
}

func ids(peers []routing.Peer) []string {
	out := make([]string, len(peers))
	for i, p := range peers {
		out[i] = p.ID
	}
	return out
}

// TestProbeRoundTrip runs the liveness rite over real loopback sockets: a healthy
// relay forwards the self-addressed probe back and passes; an unreachable relay
// fails.
func TestProbeRoundTrip(t *testing.T) {
	mk := func() (*Transfer, string) {
		xpriv, _, err := encryption.GenerateX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}
		spub, spriv, _ := ed25519.GenerateKey(nil)
		id := protocol.DeriveNodeID(spub)
		tr, err := NewTransfer(nil, nil, id, nil, nil, xpriv, spriv, 0, 1, 0, 0, false, 0)
		if err != nil {
			t.Skipf("cannot bind data port in this environment: %v", err)
		}
		tr.Start()
		return tr, id
	}

	prober, _ := mk()
	defer prober.Stop()
	relay, relayID := mk()
	defer relay.Stop()

	relayNode := &discovery.Node{
		ID:      relayID,
		PubKey:  relay.nodePriv.PublicKey().Bytes(),
		Address: "127.0.0.1:1",
		Port:    uint16(relay.Port()),
	}
	if !prober.probeRelay(relayNode) {
		t.Fatal("a healthy relay must pass the forwarding challenge")
	}

	// An unreachable relay (closed port) fails the challenge.
	deadNode := &discovery.Node{
		ID:      relayID,
		PubKey:  relay.nodePriv.PublicKey().Bytes(),
		Address: "127.0.0.1:1",
		Port:    1,
	}
	if prober.probeRelay(deadNode) {
		t.Fatal("an unreachable relay must fail the challenge")
	}
}
