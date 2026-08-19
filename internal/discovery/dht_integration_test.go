package discovery

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// newDHTNode brings up a real discovery node on an ephemeral UDP port with a
// key-bound identity, so FIND_NODE key-binding checks pass.
func newDHTNode(t *testing.T, tag byte) (*Discovery, string) {
	t.Helper()
	spub, spriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := protocol.DeriveNodeID(spub)
	d, err := NewDiscovery(id, 0)
	if err != nil {
		t.Skipf("cannot bind ephemeral UDP port: %v", err)
	}
	d.SetSigningKey(spriv)
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = tag
	}
	d.SetIdentity(pub, 5000, nil)
	d.Start()
	return d, id
}

// TestDHTFindNodeTransitive verifies A can locate C through B using FIND_NODE,
// without A ever having contacted C directly.
func TestDHTFindNodeTransitive(t *testing.T) {
	a, _ := newDHTNode(t, 0xa1)
	b, _ := newDHTNode(t, 0xb2)
	c, cid := newDHTNode(t, 0xc3)
	defer a.Stop()
	defer b.Stop()
	defer c.Stop()

	aAddr := fmt.Sprintf("127.0.0.1:%d", a.Port())
	bAddr := fmt.Sprintf("127.0.0.1:%d", b.Port())
	cAddr := fmt.Sprintf("127.0.0.1:%d", c.Port())

	// A <-> B mutual; B <-> C mutual; A and C are never wired together.
	a.SetBootstrapPeers([]string{bAddr})
	b.SetBootstrapPeers([]string{aAddr, cAddr})
	c.SetBootstrapPeers([]string{bAddr})

	// Exchange bootstrap discovery so the routing tables populate (well within
	// the 30s gossip interval, so A cannot learn C via gossip).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.Bootstrap()
		b.Bootstrap()
		c.Bootstrap()
		time.Sleep(150 * time.Millisecond)

		if _, ok := a.lookupLocal(cid); ok {
			t.Fatal("A learned C directly; test topology is not isolating the DHT lookup")
		}
		// Once A knows B and B knows C, the transitive lookup should work.
		a.mu.RLock()
		aKnows := len(a.nodes)
		a.mu.RUnlock()
		b.mu.RLock()
		_, bKnowsC := b.nodes[cid]
		b.mu.RUnlock()
		if aKnows > 0 && bKnowsC {
			break
		}
	}

	node, ok := a.FindNode(cid)
	if !ok || node == nil || node.ID != cid {
		t.Fatalf("A.FindNode(C) failed to locate C transitively via B (ok=%v)", ok)
	}
}
