package discovery

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// newReachNode brings up a discovery node advertising dataPort as its data port.
func newReachNode(t *testing.T, dataPort uint16) *Discovery {
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
	d.SetIdentity(pub, dataPort, nil)
	d.Start()
	t.Cleanup(func() { d.Stop() })
	return d
}

// bootstrapInto makes each of peers bootstrap to hub until hub has learned them
// all, so hub can probe them.
func bootstrapInto(t *testing.T, hub *Discovery, peers ...*Discovery) {
	t.Helper()
	hubAddr := fmt.Sprintf("127.0.0.1:%d", hub.Port())
	for _, p := range peers {
		p.SetBootstrapPeers([]string{hubAddr})
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range peers {
			p.Bootstrap()
		}
		time.Sleep(120 * time.Millisecond)
		if len(hub.GetActiveNodes()) >= len(peers) {
			return
		}
	}
	t.Fatalf("hub only learned %d/%d peers", len(hub.GetActiveNodes()), len(peers))
}

// TestReachabilityReachable: a node whose data port has a live listener is
// concluded reachable when a peer dials it back.
func TestReachabilityReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	dataPort := uint16(ln.Addr().(*net.TCPAddr).Port)

	a := newReachNode(t, dataPort)
	b := newReachNode(t, 1)
	bootstrapInto(t, a, b) // a learns b, so a can probe b

	got := make(chan bool, 1)
	a.EnableReachabilityChecks(func(r bool) { got <- r })

	a.checkReachability()
	select {
	case r := <-got:
		if !r {
			t.Fatal("open data port must be concluded reachable")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("no reachability determination")
	}
	if r, known := a.Reachable(); !known || !r {
		t.Fatalf("Reachable() = %v/%v, want true/true", r, known)
	}
}

// TestReachabilityUnreachable: a node whose advertised data port is closed is
// concluded unreachable once enough peers fail to dial it back.
func TestReachabilityUnreachable(t *testing.T) {
	// Bind then immediately free a port so it is guaranteed closed.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := uint16(tmp.Addr().(*net.TCPAddr).Port)
	tmp.Close()

	a := newReachNode(t, closedPort)
	b := newReachNode(t, 1)
	c := newReachNode(t, 1)
	bootstrapInto(t, a, b, c) // a needs >=2 peers to conclude unreachable

	got := make(chan bool, 1)
	a.EnableReachabilityChecks(func(r bool) { got <- r })

	a.checkReachability()
	select {
	case r := <-got:
		if r {
			t.Fatal("closed data port must be concluded unreachable")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("no reachability determination")
	}
	if r, known := a.Reachable(); !known || r {
		t.Fatalf("Reachable() = %v/%v, want false/true", r, known)
	}
}
