package discovery

import (
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/iface"
	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// recordingIface is a stub interface that just counts where frames were sent,
// separating broadcast from point-to-point.
type recordingIface struct {
	mu      sync.Mutex
	bcast   int
	unicast int
	frames  chan iface.InboundFrame
}

func (r *recordingIface) Name() string     { return "rec" }
func (r *recordingIface) Kind() iface.Kind { return iface.KindUDP }
func (r *recordingIface) Caps() iface.Caps { return iface.Caps{} }
func (r *recordingIface) Send(addr string, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if addr == iface.Broadcast {
		r.bcast++
	} else {
		r.unicast++
	}
	return nil
}
func (r *recordingIface) Frames() <-chan iface.InboundFrame {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frames == nil {
		r.frames = make(chan iface.InboundFrame)
	}
	return r.frames
}
func (r *recordingIface) Close() error { return nil }
func (r *recordingIface) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bcast, r.unicast
}

// announceWithRelays builds a genuine self-signed announce that advertises circuit
// reservation relays — how a NAT'd node says "reach me through these".
func announceWithRelays(t *testing.T, priv ed25519.PrivateKey, id string, hop uint8, relayIDs []string) (*protocol.Packet, *protocol.AnnouncePayload) {
	t.Helper()
	ap := protocol.AnnouncePayload{
		DestHash:  id,
		PubKey:    []byte{9, 8, 7, 6},
		Port:      9100,
		RelayIDs:  relayIDs,
		Timestamp: time.Now().UnixNano(),
		Nonce:     randUint64(),
		HopCount:  hop,
	}
	ap.Sign(priv)
	data, err := json.Marshal(&ap)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.NewPacket(protocol.PacketTypeAnnounce, data, "ANY", ""), &ap
}

// TestAnnounce_CarriesRelayIDsAcrossForwarding is the replacement channel for what
// gossip used to do, and the reason the gossip hole could be closed at all.
//
// A NAT'd node is unreachable by definition, so its reservations have to reach
// senders indirectly. Gossip did that unauthenticated. An announce does it with the
// announcer's own signature, which survives re-forwarding — so a relayed copy is
// still the announcer's statement about itself, and a forwarder cannot alter it.
//
// The forwarded (HopCount > 0) case is the one that matters: it is exactly the case
// gossip existed to serve.
func TestAnnounce_CarriesRelayIDsAcrossForwarding(t *testing.T) {
	for _, hop := range []uint8{0, 3} {
		t.Run(map[bool]string{true: "direct", false: "forwarded"}[hop == 0], func(t *testing.T) {
			d := newTestDiscovery("self")
			priv, id := newIdentity(t)
			relayID := "e8960f49c5a75b8011f6e167c3caef25"

			pkt, _ := announceWithRelays(t, priv, id, hop, []string{relayID})
			if !d.handleAnnounce(testHop, nil, pkt) {
				t.Fatal("announce was not accepted")
			}

			node, ok := d.nodes[id]
			if !ok {
				t.Fatal("announced node was not learned")
			}
			if len(node.RelayIDs) != 1 || node.RelayIDs[0] != relayID {
				t.Fatalf("RelayIDs = %v, want [%s] — a NAT'd node's reservations must "+
					"survive the announce path, or it becomes unreachable", node.RelayIDs, relayID)
			}
		})
	}
}

// TestAnnounce_RelayIDsAreTamperEvident proves the property that makes the above
// safe to trust from a forwarder: a hop that rewrites RelayIDs to point at itself
// invalidates the announcer's signature, so the tampered announce is dropped rather
// than believed. This is precisely the attack gossip permitted.
func TestAnnounce_RelayIDsAreTamperEvident(t *testing.T) {
	priv, id := newIdentity(t)
	_, ap := announceWithRelays(t, priv, id, 1, []string{"honest-relay"})

	if !ap.VerifyBound() {
		t.Fatal("genuine announce failed to verify")
	}

	// A malicious forwarder substitutes its own relay.
	ap.RelayIDs = []string{"attacker-relay"}
	if ap.VerifyBound() {
		t.Fatal("tampered RelayIDs still verified: a forwarder could name itself as " +
			"any NAT'd node's reservation relay and capture all traffic to it")
	}

	// Deleting the field entirely must be caught too — otherwise an attacker could
	// strip reservations to make a NAT'd node unreachable.
	ap.RelayIDs = nil
	if ap.VerifyBound() {
		t.Fatal("stripped RelayIDs still verified: a forwarder could silently make a " +
			"NAT'd node unreachable")
	}
}

// TestAnnounce_NoRelayIDsKeepsLegacyEncoding guards the compatibility decision.
// RelayIDs is appended to the signed bytes only when non-empty, so an announce
// carrying none hashes exactly as it did before the field existed and stays
// mutually verifiable with older peers. nil and empty must behave identically.
func TestAnnounce_NoRelayIDsKeepsLegacyEncoding(t *testing.T) {
	priv, id := newIdentity(t)

	nilAP := protocol.AnnouncePayload{
		DestHash: id, PubKey: []byte{1}, Port: 1, Timestamp: 42, Nonce: 7, RelayIDs: nil,
	}
	nilAP.Sign(priv)

	emptyAP := nilAP
	emptyAP.RelayIDs = []string{}
	if !emptyAP.VerifySig() {
		t.Fatal("empty RelayIDs changed the signed encoding; nil and empty must be " +
			"indistinguishable or peers disagree on the same announce")
	}

	// And adding a reservation must change it — otherwise the field is not covered.
	withAP := nilAP
	withAP.RelayIDs = []string{"r1"}
	if withAP.VerifySig() {
		t.Fatal("RelayIDs is not covered by the signature")
	}
}

// TestAnnounce_FloodsPointToPoint guards the propagation half of the fix. Signing
// RelayIDs into the announce is only useful if the announce actually reaches the
// peers that must route to the announcer. Flooding by broadcast alone never leaves
// the local link, so a NAT'd node's reservations reached nobody and unauthenticated
// gossip remained the only channel that carried them — which is exactly what the
// security fix removed. Announces must also go point-to-point to known peers.
func TestAnnounce_FloodsPointToPoint(t *testing.T) {
	d, _ := realDiscovery(t)
	defer d.Stop()

	// A peer we have verified first-hand, reachable only by unicast.
	peerID, peerKey := identity(t)
	d.updateNode(peerID, "127.0.0.1:59999", []byte("px"), peerKey, 59999, nil, nil, nil)
	d.mu.Lock()
	d.nodes[peerID].Active = true
	d.mu.Unlock()

	rec := &recordingIface{}
	d.mu.Lock()
	d.ifaces = []iface.Interface{rec}
	d.iface = rec
	d.mu.Unlock()

	d.announceSelf()

	bcast, unicast := rec.counts()
	if bcast == 0 {
		t.Error("announce was not broadcast; link-local discovery would stop working")
	}
	if unicast == 0 {
		t.Fatalf("announce was broadcast only (%d frames) and never sent to the known "+
			"peer: a NAT'd peer shares no broadcast domain with us, so its signed "+
			"reservations would never reach anyone", bcast)
	}
}
