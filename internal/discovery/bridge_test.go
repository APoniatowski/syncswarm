package discovery

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// realDiscovery builds a Discovery with a real key-bound identity and an open UDP
// socket on an ephemeral port, so its UDP broadcasts do not reach another node on
// a different ephemeral port — simulating separate broadcast domains.
func realDiscovery(t *testing.T, caps ...string) (*Discovery, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := protocol.DeriveNodeID(pub)
	d, err := NewDiscovery(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	d.SetSigningKey(priv)
	d.SetIdentity([]byte{1, 2, 3, 4, 5, 6, 7, 8}, uint16(d.Port()), caps)
	return d, id
}

// TestBridge_CrossesBroadcastDomains proves that two nodes which cannot reach each
// other by UDP broadcast (distinct ephemeral ports) still discover each other over
// a TCP bridge: announces fan out across the bridge and build path tables on both
// ends. This is the connection-agnostic, DNS-free cross-subnet discovery.
func TestBridge_CrossesBroadcastDomains(t *testing.T) {
	// B is the transport node accepting bridges.
	b, bid := realDiscovery(t, "relay")
	srvAddr, err := b.AddListenBridge("srv", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// A bridges to B over TCP (as a client behind NAT would).
	a, aid := realDiscovery(t)
	if err := a.AddBridge("cli", srvAddr); err != nil {
		t.Fatal(err)
	}

	a.Start()
	defer a.Stop()
	b.Start()
	defer b.Stop()

	// Re-announce each round to defeat any connection-registration race; the
	// periodic tick is a full minute, too slow for a test.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.announceSelf()
		b.announceSelf()
		_, _, aHasB := a.PathTo(bid)
		_, _, bHasA := b.PathTo(aid)
		if aHasB && bHasA {
			return // mutual discovery across the bridge
		}
		time.Sleep(100 * time.Millisecond)
	}

	_, _, aHasB := a.PathTo(bid)
	_, _, bHasA := b.PathTo(aid)
	t.Fatalf("bridge discovery failed: A learned B = %v, B learned A = %v", aHasB, bHasA)
}

// TestBridge_UnicastCrossesBridge proves unicast (not just broadcast) routes over
// a bridge: A measures latency to B — a request/reply exchange — and both the
// check and the reply must traverse the TCP bridge, since A and B share no UDP
// broadcast domain. This exercises the per-node interface routing (ifaceFor).
func TestBridge_UnicastCrossesBridge(t *testing.T) {
	b, bid := realDiscovery(t, "relay")
	srvAddr, err := b.AddListenBridge("srv", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := realDiscovery(t)
	if err := a.AddBridge("cli", srvAddr); err != nil {
		t.Fatal(err)
	}
	a.Start()
	defer a.Stop()
	b.Start()
	defer b.Stop()

	// Wait until A has learned B over the bridge (so ifaceFor(B) is the bridge).
	deadline := time.Now().Add(5 * time.Second)
	var bnode *Node
	for time.Now().Before(deadline) {
		a.announceSelf()
		b.announceSelf()
		a.mu.RLock()
		bnode = a.nodes[bid]
		a.mu.RUnlock()
		if bnode != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if bnode == nil {
		t.Fatal("A never learned B over the bridge")
	}

	// The latency check and its reply must both cross the bridge; a real RTT
	// (under maxLatency) proves the round trip completed over TCP.
	if lat := a.measureLatency(bnode); lat >= maxLatency {
		t.Fatalf("latency to B = %v (>= maxLatency); unicast did not cross the bridge", lat)
	}
}
