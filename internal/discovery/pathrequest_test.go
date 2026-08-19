package discovery

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

func pathRequestPacket(t *testing.T, destHash string, nonce uint64, hop uint8) *protocol.Packet {
	t.Helper()
	pr := protocol.PathRequestPayload{DestHash: destHash, Nonce: nonce, HopCount: hop}
	data, err := json.Marshal(&pr)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.NewPacket(protocol.PacketTypePathRequest, data, "ANY", "")
}

// withSigningKey gives a socket-free test Discovery a real identity so it can
// build/sign its own announce in response to a path request.
func withSigningKey(d *Discovery, priv ed25519.PrivateKey) {
	d.signPriv = priv
	d.signPub = priv.Public().(ed25519.PublicKey)
}

func TestPathRequest_DestinationRespondsWithOwnAnnounce(t *testing.T) {
	priv, id := newIdentity(t)
	d := newTestDiscovery(id)
	withSigningKey(d, priv)

	ap, forwarded := d.handlePathRequest(pathRequestPacket(t, id, 1, 0))
	if ap == nil {
		t.Fatal("destination should answer a path request for itself")
	}
	if ap.DestHash != id || !ap.VerifyBound() {
		t.Fatalf("response announce invalid: dest=%q bound=%v", ap.DestHash, ap.VerifyBound())
	}
	if forwarded {
		t.Fatal("destination should answer, not forward")
	}
}

func TestPathRequest_TransportReAnnouncesCachedPath(t *testing.T) {
	d := newTestDiscovery("selfB")
	d.capabilities = []string{"relay"} // transport

	xpriv, xid := newIdentity(t)
	// Cache X's announce at 3 hops via a prior announce.
	if !d.handleAnnounce(testHop, nil, signedAnnounce(t, xpriv, xid, 3, time.Now().UnixNano(), 1)) {
		t.Fatal("announce for X should be stored")
	}

	ap, forwarded := d.handlePathRequest(pathRequestPacket(t, xid, 9, 0))
	if ap == nil {
		t.Fatal("transport holding a cached path should re-announce it")
	}
	if ap.DestHash != xid || !ap.VerifyBound() {
		t.Fatalf("re-announce invalid: dest=%q bound=%v", ap.DestHash, ap.VerifyBound())
	}
	if ap.HopCount != 4 {
		t.Fatalf("re-announce HopCount = %d, want 4 (cached 3 + 1)", ap.HopCount)
	}
	if forwarded {
		t.Fatal("should answer from cache, not forward")
	}
}

func TestPathRequest_TransportForwardsWhenUnknown(t *testing.T) {
	d := newTestDiscovery("selfT")
	d.capabilities = []string{"relay"}
	withSigningKey(d, mustKey(t))

	ap, forwarded := d.handlePathRequest(pathRequestPacket(t, "ffffffffffffffffffffffffffffffff", 2, 0))
	if ap != nil {
		t.Fatal("no cached path -> no announce response")
	}
	if !forwarded {
		t.Fatal("a transport should flood an unknown-destination request further")
	}
}

func TestPathRequest_EndpointDropsWhenUnknown(t *testing.T) {
	d := newTestDiscovery("selfE") // no "relay" capability => endpoint
	ap, forwarded := d.handlePathRequest(pathRequestPacket(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 3, 0))
	if ap != nil || forwarded {
		t.Fatalf("endpoint should neither answer nor forward: ap=%v forwarded=%v", ap, forwarded)
	}
}

func TestPathRequest_Dedup(t *testing.T) {
	priv, id := newIdentity(t)
	d := newTestDiscovery(id)
	withSigningKey(d, priv)

	if ap, _ := d.handlePathRequest(pathRequestPacket(t, id, 5, 0)); ap == nil {
		t.Fatal("first request should be answered")
	}
	if ap, _ := d.handlePathRequest(pathRequestPacket(t, id, 5, 0)); ap != nil {
		t.Fatal("duplicate request (same DestHash,Nonce) should be dropped")
	}
}

func TestResolvePath_ShortCircuitsWhenKnown(t *testing.T) {
	d := newTestDiscovery("self")
	xpriv, xid := newIdentity(t)
	if !d.handleAnnounce(testHop, nil, signedAnnounce(t, xpriv, xid, 1, time.Now().UnixNano(), 1)) {
		t.Fatal("announce should be stored")
	}
	// A path already exists, so ResolvePath returns immediately without needing an
	// interface to flood a request.
	if !d.ResolvePath(xid, 10*time.Millisecond) {
		t.Fatal("ResolvePath should return true when a path is already known")
	}
	if d.ResolvePath("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 60*time.Millisecond) {
		t.Fatal("ResolvePath should time out (false) for an unreachable destination")
	}
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
