package swarmsync

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// TestNATdPeerReservationsReachSender reproduces the live topology that kept
// failing in the field, deterministically and in-process.
//
//	A (sender)  ──►  R (relay, reachable)  ◄──  C (NAT'd receiver, NeedsRelay)
//
// A and C never learn each other directly; both know only R. C holds a circuit
// reservation with R and advertises it in RelayIDs. For A to route anything to C,
// A must learn those RelayIDs — and since the security fix they may only come from
// C's own signed announce, not from third-party gossip.
//
// This asserts the propagation path end to end: C's signed announce reaches R, and
// R hands it back to A when A asks for a route to C.
func TestNATdPeerReservationsReachSender(t *testing.T) {
	key := bytes.Repeat([]byte{0x51}, 32)

	r := newTestNode(t, Options{NodeID: "r", Key: key, Relay: true})
	a := newTestNode(t, Options{NodeID: "a", Key: key})
	recv := make(chan []byte, 4)
	c := newTestNode(t, Options{
		NodeID: "c", Key: key,
		NeedsRelay:     true, // the peer is behind NAT: it must reserve to be reachable
		AutoRelay:      true,
		OnDataReceived: func(b []byte) { recv <- b },
	})
	all := []*SyncSwarm{r, a, c}
	for _, n := range all {
		if n.DiscoveryPort() == 0 || n.DataPort() == 0 {
			t.Skip("could not bind ephemeral ports in this environment")
		}
	}

	disc := func(n *SyncSwarm) string { return fmt.Sprintf("127.0.0.1:%d", n.DiscoveryPort()) }
	a.SetBootstrapPeers([]string{disc(r)})          // A knows only the relay
	c.SetBootstrapPeers([]string{disc(r)})          // C knows only the relay
	r.SetBootstrapPeers([]string{disc(a), disc(c)}) // the relay knows both, as a seed does

	for _, n := range all {
		if err := n.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		t.Cleanup(func() { n.Stop() })
	}

	// First: C must actually obtain a reservation, or there is nothing to learn.
	var cRelays []string
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range all {
			n.Bootstrap()
		}
		time.Sleep(300 * time.Millisecond)
		for _, p := range r.Peers() {
			if p.ID == c.NodeID() && len(p.RelayIDs) > 0 {
				cRelays = p.RelayIDs
			}
		}
		if len(cRelays) > 0 {
			break
		}
	}
	for _, p := range r.Peers() {
		t.Logf("R sees %s active=%v caps=%v relay_ids=%v", p.ID[:6], p.Active, p.Capabilities, p.RelayIDs)
	}
	t.Logf("counts: R=%d A=%d C=%d peers", len(r.Peers()), len(a.Peers()), len(c.Peers()))
	for _, p := range a.Peers() {
		t.Logf("A sees %s active=%v caps=%v relay_ids=%v", p.ID[:6], p.Active, p.Capabilities, p.RelayIDs)
	}
	for _, p := range c.Peers() {
		t.Logf("C sees %s active=%v caps=%v relay_ids=%v", p.ID[:6], p.Active, p.Capabilities, p.RelayIDs)
	}
	t.Logf("R id=%s A id=%s C id=%s", r.NodeID()[:6], a.NodeID()[:6], c.NodeID()[:6])
	t.Logf("C reachable=%v", func() string { rr, kn := c.Reachable(); return fmt.Sprintf("%v/known=%v", rr, kn) }())
	if len(cRelays) == 0 {
		t.Fatal("the relay never learned the NAT'd peer's reservations; nothing " +
			"downstream can work")
	}

	// Then the part that was broken in the field. RelayIDs propagate on demand:
	// the path request that fetches the destination's signed announce is issued by
	// the send path itself, so this must be driven by an actual send, not by
	// polling the peer table.
	payload := []byte("delivered-to-a-natted-peer")
	deadline = time.Now().Add(40 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		a.Bootstrap()
		if err := a.SendTo(payload, c.NodeID()); err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		select {
		case got := <-recv:
			if !bytes.Equal(got, payload) {
				t.Fatalf("delivered %d bytes, want %d", len(got), len(payload))
			}
			return // success: reached a NAT'd peer through its circuit reservation
		case <-time.After(2 * time.Second):
			lastErr = fmt.Errorf("send reported success but nothing arrived")
		}
	}
	t.Fatalf("never delivered to the NAT'd peer (relay holds %v); last error: %v",
		cRelays, lastErr)
}
