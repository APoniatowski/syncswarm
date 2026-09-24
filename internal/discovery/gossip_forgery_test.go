package discovery

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// identity mints a real, key-bound identity: an ID that genuinely derives from a
// signing key, which is all a gossip record is required to prove.
func identity(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.DeriveNodeID(pub), pub
}

// TestGossip_CannotForgeVictimReservationRelays is an exploit test for the
// strongest attack the gossip channel currently permits against a NAT'd user.
//
// The attack: a NAT'd victim is only reachable through the relays it holds circuit
// reservations with (RelayIDs), and when a sender knows those relays it collapses
// the onion path to exactly one of them (transfer.pickReservationRelay). So an
// attacker who can dictate a victim's RelayIDs dictates the sole hop that every
// message to that victim traverses.
//
// RelayIDs cannot be forged on the direct path: a discovery packet is only
// accepted when payload.NodeID == packet.SignerID(), so a node's reservation
// relays are attested by the node itself. But the same field also rides in gossip,
// where the only check is that the *subject's* ID derives from the *subject's*
// signing key — both of which are public, broadcast in every announce. The record
// is signed by the gossiper, who is not the subject, and nothing binds the
// remaining fields to the subject at all.
//
// So any swarm member can assert arbitrary RelayIDs for any node whose announce
// they have seen, and thereby install themselves as the exclusive last hop.
//
// Content stays sealed — the attacker peels only its own onion layer — but it
// learns who is talking to the victim, when, and how much, and can silently drop
// all of it. For a privacy-respecting SDK, that is the whole threat model.
//
// This test asserts the fix: gossip may not overwrite a subject-attested fact.
func TestGossip_CannotForgeVictimReservationRelays(t *testing.T) {
	d := newTestDiscovery("self")

	victimID, victimKey := identity(t)
	honestRelayID, _ := identity(t)
	attackerID, attackerKey := identity(t)

	// The victim advertises its genuine reservation relay on the subject-bound
	// path: this is the victim's own signed statement about itself.
	d.updateNode(victimID, "203.0.113.9:9000", []byte("vx"), victimKey, 9000,
		nil, []string{honestRelayID}, nil)

	// The attacker is a real, reachable, relay-capable node. Nothing here is
	// forged — running an honest-looking relay is the price of entry.
	d.updateNode(attackerID, "198.51.100.7:9000", []byte("ax"), attackerKey, 9000,
		[]string{"relay"}, nil, nil)

	// The attack itself: one gossip record, correctly key-bound to the victim,
	// naming the attacker as the victim's reservation relay.
	d.mergePeer(protocol.PeerInfo{
		NodeID:   victimID,
		SignKey:  victimKey,
		PubKey:   []byte("vx"),
		Port:     9000,
		RelayIDs: []string{attackerID},
		LastSeen: time.Now(),
	}, false)

	got, ok := d.NodeByID(victimID)
	if !ok {
		t.Fatal("victim disappeared from the node table")
	}
	for _, id := range got.RelayIDs {
		if id == attackerID {
			t.Fatalf("gossip forged the victim's reservation relays: RelayIDs=%v.\n"+
				"An attacker running one honest relay can now become the sole hop for "+
				"all traffic to this NAT'd node, seeing every sender, timing and volume.",
				got.RelayIDs)
		}
	}
	if len(got.RelayIDs) != 1 || got.RelayIDs[0] != honestRelayID {
		t.Fatalf("victim's self-attested relays were not preserved: got %v, want [%s]",
			got.RelayIDs, honestRelayID)
	}
}

// TestGossip_CannotForgeCapabilities covers the same provenance hole in the field
// that decides who is eligible to carry traffic at all. Gossip claiming "relay"
// for a node can pull that node into other peers' relay sets; gossip claiming it
// for a NAT'd node yields paths that cannot be built.
func TestGossip_CannotForgeCapabilities(t *testing.T) {
	d := newTestDiscovery("self")

	victimID, victimKey := identity(t)
	d.updateNode(victimID, "203.0.113.9:9000", []byte("vx"), victimKey, 9000, nil, nil, nil)

	d.mergePeer(protocol.PeerInfo{
		NodeID:       victimID,
		SignKey:      victimKey,
		PubKey:       []byte("vx"),
		Port:         9000,
		Capabilities: []string{"relay"},
		LastSeen:     time.Now(),
	}, false)

	got, _ := d.NodeByID(victimID)
	for _, c := range got.Capabilities {
		if c == "relay" {
			t.Fatalf("gossip forged capabilities for a node that never claimed them: %v",
				got.Capabilities)
		}
	}
}

// TestGossip_SelfAttestedRecordIsHonoured is the counterpart to the two tests
// above, and guards a regression that reached live relays: rejecting *all*
// capability and reservation claims from gossip also rejected the legitimate ones.
//
// A gossip payload is signed by its sender, so the entry describing the sender
// itself is a first-party statement with exactly the authority of a direct
// discovery packet. Dropping it meant a node learned no peer capabilities until a
// signed announce happened to arrive — and a NAT'd node that cannot see any
// relay-capable peer cannot obtain a circuit reservation, so it never becomes
// reachable at all. Observed in the field as `caps=[]` persisting for minutes
// against two known-good relays.
func TestGossip_SelfAttestedRecordIsHonoured(t *testing.T) {
	d := newTestDiscovery("self")

	relayID, relayKey := identity(t)
	reservedWith := "e8960f49c5a75b8011f6e167c3caef25"

	// The relay gossips its own record: subject and signer are the same node.
	d.mergePeer(protocol.PeerInfo{
		NodeID:       relayID,
		SignKey:      relayKey,
		PubKey:       []byte("rx"),
		Address:      "203.0.113.1:64512",
		Port:         64512,
		Capabilities: []string{"relay"},
		RelayIDs:     []string{reservedWith},
		LastSeen:     time.Now(),
	}, true)

	got, ok := d.NodeByID(relayID)
	if !ok {
		t.Fatal("self-attested peer was not added")
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "relay" {
		t.Fatalf("Capabilities = %v, want [relay]: a peer describing itself in a "+
			"message it signed is first-party, not hearsay", got.Capabilities)
	}
	if len(got.RelayIDs) != 1 || got.RelayIDs[0] != reservedWith {
		t.Fatalf("RelayIDs = %v, want [%s]", got.RelayIDs, reservedWith)
	}
}
