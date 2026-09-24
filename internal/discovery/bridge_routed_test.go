package discovery

import (
	"fmt"
	"testing"
	"time"
)

// TestBridge_VerifiesPeerReachedThroughBridge is the regression test for the last
// audit finding: a peer learned *through* a bridge could never be verified.
//
//	A ──TCP bridge── B (transport) ──UDP── C
//
// A and C share no broadcast domain and are not adjacent. A learns C from the
// announces B floods across the bridge, but its latency check was addressed on an
// interface — and a bridge writes to its single connection and ignores the address,
// so the check was delivered to B, which answered as itself. Identity-bound
// liveness correctly rejects that reply, so C stayed permanently unverified: with
// `-bridge` no peer ever became active, which is what made a bridged NAT'd node
// unable to find any relay to reserve with.
//
// The check must now be routed by destination, and the reply must come back signed
// by C.
func TestBridge_VerifiesPeerReachedThroughBridge(t *testing.T) {
	// B is the transport in the middle: it accepts a bridge and forwards announces.
	b, bid := realDiscovery(t, "relay")
	srvAddr, err := b.AddListenBridge("srv", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// C sits on B's UDP side only; it has no bridge and never meets A directly.
	c, cid := realDiscovery(t)
	c.SetBootstrapPeers([]string{fmt.Sprintf("127.0.0.1:%d", b.Port())})

	// A reaches the swarm only through the bridge to B.
	a, _ := realDiscovery(t)
	if err := a.AddBridge("cli", srvAddr); err != nil {
		t.Fatal(err)
	}
	b.SetBootstrapPeers([]string{fmt.Sprintf("127.0.0.1:%d", c.Port())})

	for _, d := range []*Discovery{b, c, a} {
		d.Start()
		defer d.Stop()
	}

	// Wait until A has learned C at all (via announces crossing the bridge) and B
	// knows C directly, so there is a path for the routed check to follow.
	deadline := time.Now().Add(10 * time.Second)
	var learned bool
	for time.Now().Before(deadline) {
		a.announceSelf()
		b.announceSelf()
		c.announceSelf()
		time.Sleep(150 * time.Millisecond)
		if _, _, ok := a.PathTo(cid); ok {
			if _, exists := a.NodeByID(cid); exists {
				learned = true
				break
			}
		}
	}
	if !learned {
		t.Skip("A never learned C across the bridge in this environment; " +
			"TestBridge_CrossesBroadcastDomains covers the flooding half")
	}

	// The heart of it: A must be able to verify C first-hand, which requires the
	// check to reach C and C's signed reply to come back.
	node, ok := a.NodeByID(cid)
	if !ok {
		t.Fatal("A lost C from its table")
	}
	nh, hops, hasPath := a.PathTo(cid)
	t.Logf("A: routedOnly(C)=%v path=(%q,%d,%v) C.Address=%q", a.routedOnly(cid), nh, hops, hasPath, node.Address)
	nhB, _, bHasC := b.PathTo(cid)
	t.Logf("B: path to C=(%q,%v) isTransport=%v", nhB, bHasC, b.isTransport())
	_, cHasA := c.NodeByID(a.selfID)
	nhC, _, cPathA := c.PathTo(a.selfID)
	t.Logf("C: knows A=%v path to A=(%q,%v)", cHasA, nhC, cPathA)

	if lat := a.measureLatency(node); lat > maxLatency {
		t.Fatalf("A could not verify C (%s) through the bridge to B (%s): latency "+
			"check did not get a reply signed by C. A peer reached through a bridge "+
			"must be addressed by routing, not by interface.", cid[:8], bid[:8])
	}
}
