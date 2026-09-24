package transfer

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/APoniatowski/syncswarm/internal/discovery"
	"github.com/APoniatowski/syncswarm/internal/routing"
)

// TestReservation_KeepsPathDiversity is the regression guard for SECURITY_AUDIT.md
// finding 1.
//
// A NAT'd destination must be entered through a relay it holds a reservation with,
// so that relay has to be the exit hop. The bug was that satisfying this constraint
// discarded every other relay (`relays = []routing.Peer{*rr}`), which dragged hop
// count and path count down with it: the path became a single hop, and that one
// relay saw the sender's address and the destination together.
//
// The effect was that enabling NeedsRelay — the flag a user sets precisely because
// they are behind NAT and want the relay network — silently switched off the
// anonymity that onion routing provides. This asserts the exit constraint is met
// without sacrificing the rest of the path.
func TestReservation_KeepsPathDiversity(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tr := &Transfer{nodePriv: priv, hopCount: 3, redundancy: 1}

	// Eight relays in distinct subnets; the destination reserved with exactly one.
	const reservedWith = "r5"
	var nodes []*discovery.Node
	for _, p := range distinctRelays(8) {
		nodes = append(nodes, &discovery.Node{
			ID: p.ID, Address: p.Address, Port: 1,
			Active: true, Capabilities: []string{"relay"}, PubKey: priv.PublicKey().Bytes(),
		})
	}
	dest := &discovery.Node{
		ID: "natted-dest", Address: "203.0.113.9", Port: 9000,
		Active: false, PubKey: priv.PublicKey().Bytes(),
		RelayIDs: []string{reservedWith},
	}

	fc, err := tr.newForwardCtx(dest, nodes, [32]byte{}, scheme{}, nil)
	if err != nil {
		t.Fatalf("newForwardCtx: %v", err)
	}

	if len(fc.relays) < 2 {
		t.Fatalf("relay set collapsed to %d relay(s): a NAT'd destination lost onion "+
			"path diversity, so the reservation relay sees sender and destination together",
			len(fc.relays))
	}
	if !fc.exitNear[reservedWith] {
		t.Fatalf("exitNear = %v, must contain the reservation relay %q so it is pinned "+
			"to the exit hop", fc.exitNear, reservedWith)
	}

	// And the constraint still actually binds: the built path must exit at the
	// relay holding the reservation, or the fragment cannot enter the NAT'd node.
	planner := &routing.Planner{}
	path, err := planner.BuildPathTiered(
		routing.Peer{ID: dest.ID, Address: "203.0.113.9:9000", PubKey: dest.PubKey},
		fc.relays, 3, routing.PathOptions{ExitNear: fc.exitNear},
	)
	if err != nil {
		t.Fatalf("BuildPathTiered: %v", err)
	}
	if len(path) < 3 {
		t.Fatalf("path has %d hops, want multi-hop: %v", len(path), path)
	}
	// Last element is the destination; the hop before it is the exit relay.
	exit := path[len(path)-2]
	if exit.NodeID != reservedWith {
		t.Fatalf("exit hop = %q, want the reservation relay %q", exit.NodeID, reservedWith)
	}
}

// TestReservation_UnusableRelayFails checks the other half: if the destination
// advertises reservation relays but none of them are usable, there is no way in,
// and that must surface as an error rather than a path that quietly cannot deliver.
func TestReservation_UnusableRelayFails(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tr := &Transfer{nodePriv: priv, hopCount: 3, redundancy: 1}

	var nodes []*discovery.Node
	for _, p := range distinctRelays(4) {
		nodes = append(nodes, &discovery.Node{
			ID: p.ID, Address: p.Address, Port: 1,
			Active: true, Capabilities: []string{"relay"}, PubKey: priv.PublicKey().Bytes(),
		})
	}
	dest := &discovery.Node{
		ID: "natted-dest", Address: "203.0.113.9", Port: 9000,
		PubKey: priv.PublicKey().Bytes(), RelayIDs: []string{"a-relay-we-cannot-use"},
	}

	if _, err := tr.newForwardCtx(dest, nodes, [32]byte{}, scheme{}, nil); err == nil {
		t.Fatal("expected an error when no advertised reservation relay is usable")
	}
}
