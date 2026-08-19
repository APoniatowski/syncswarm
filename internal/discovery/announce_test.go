package discovery

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

var testHop = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 64512}

func newIdentity(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv, protocol.DeriveNodeID(pub)
}

// signedAnnounce builds a genuine, self-signed announce packet for an identity.
func signedAnnounce(t *testing.T, priv ed25519.PrivateKey, id string, hop uint8, ts int64, nonce uint64) *protocol.Packet {
	t.Helper()
	ap := protocol.AnnouncePayload{
		DestHash:     id,
		PubKey:       []byte{9, 8, 7, 6},
		Port:         9100,
		Capabilities: []string{"relay"},
		Timestamp:    ts,
		Nonce:        nonce,
		HopCount:     hop,
	}
	ap.Sign(priv)
	data, err := json.Marshal(&ap)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.NewPacket(protocol.PacketTypeAnnounce, data, "ANY", "")
}

func TestAnnounce_LearnedAndPathRecorded(t *testing.T) {
	d := newTestDiscovery("self")
	priv, id := newIdentity(t)
	pkt := signedAnnounce(t, priv, id, 0, time.Now().UnixNano(), 1)

	if !d.handleAnnounce(testHop, nil, pkt) {
		t.Fatal("expected announce to be accepted and stored")
	}
	if _, ok := d.nodes[id]; !ok {
		t.Fatal("announced node was not learned into the peer table")
	}
	nh, hops, ok := d.PathTo(id)
	if !ok || hops != 0 || nh != testHop.String() {
		t.Fatalf("PathTo = (%q, %d, %v), want (%q, 0, true)", nh, hops, ok, testHop.String())
	}
}

func TestAnnounce_ForgedRejected(t *testing.T) {
	d := newTestDiscovery("self")
	// Sign with a real key but claim a DestHash not derived from it: key-binding
	// must reject it so an announce cannot be forged for another node's identity.
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ap := protocol.AnnouncePayload{
		DestHash:  "00000000000000000000000000000000",
		Timestamp: time.Now().UnixNano(),
		Nonce:     2,
	}
	ap.Sign(priv)
	data, _ := json.Marshal(&ap)
	pkt := protocol.NewPacket(protocol.PacketTypeAnnounce, data, "ANY", "")

	if d.handleAnnounce(testHop, nil, pkt) {
		t.Fatal("forged announce (bad key-binding) was accepted")
	}
	if _, _, ok := d.PathTo(ap.DestHash); ok {
		t.Fatal("forged announce recorded a path")
	}
}

func TestAnnounce_SelfIgnored(t *testing.T) {
	priv, id := newIdentity(t)
	d := newTestDiscovery(id) // we are the announcer
	pkt := signedAnnounce(t, priv, id, 0, time.Now().UnixNano(), 3)

	if d.handleAnnounce(testHop, nil, pkt) {
		t.Fatal("an announce for our own ID must be ignored (loop prevention)")
	}
}

func TestAnnounce_Dedup(t *testing.T) {
	d := newTestDiscovery("self")
	priv, id := newIdentity(t)
	pkt := signedAnnounce(t, priv, id, 0, time.Now().UnixNano(), 7)

	if !d.handleAnnounce(testHop, nil, pkt) {
		t.Fatal("first announce should be stored")
	}
	if d.handleAnnounce(testHop, nil, pkt) {
		t.Fatal("re-received announce (same DestHash,Nonce) should be deduped, not re-stored")
	}
}

func TestAnnounce_FreshnessBeatsHopCount(t *testing.T) {
	d := newTestDiscovery("self")
	priv, id := newIdentity(t)

	// A newer announce at 2 hops arrives first.
	if !d.handleAnnounce(testHop, nil, signedAnnounce(t, priv, id, 2, 200, 1)) {
		t.Fatal("newer announce should be stored")
	}
	if _, hops, _ := d.PathTo(id); hops != 2 {
		t.Fatalf("hops = %d, want 2", hops)
	}
	// A staler announce (older timestamp) via a shorter 0-hop path must NOT
	// overwrite the fresher path, even though it is closer.
	otherHop := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 20), Port: 64512}
	if d.handleAnnounce(otherHop, nil, signedAnnounce(t, priv, id, 0, 100, 2)) {
		t.Fatal("stale announce should not be stored")
	}
	if _, hops, _ := d.PathTo(id); hops != 2 {
		t.Fatalf("after stale announce hops = %d, want 2 (freshness beats hop count)", hops)
	}
}

func TestAnnounce_TransportForwards(t *testing.T) {
	d, err := NewDiscovery("selfnode", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	d.SetSigningKey(priv)
	d.SetIdentity(nil, uint16(d.Port()), []string{"relay"}) // transport node

	apriv, id := newIdentity(t)
	pkt := signedAnnounce(t, apriv, id, 0, time.Now().UnixNano(), 5)

	if !d.handleAnnounce(testHop, nil, pkt) {
		t.Fatal("transport should accept and store the announce")
	}
	// The forward runs in a goroutine after a randomized spread delay; give it
	// time to fire so the -race detector exercises the re-broadcast path.
	time.Sleep(announceSpreadMax + 100*time.Millisecond)
	if _, _, ok := d.PathTo(id); !ok {
		t.Fatal("path to announced node should be recorded")
	}
}
