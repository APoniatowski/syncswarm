package transfer

import (
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/routing"
)

// TestCoverTrafficDropped verifies a decoy is routed like real traffic but the
// exit node drops it instead of delivering it to the application.
func TestCoverTrafficDropped(t *testing.T) {
	dpriv, dpub, _ := encryption.GenerateX25519KeyPair()
	delivered := make(chan struct{}, 1)
	dest := &Transfer{
		selfID:   "dest",
		nodePriv: dpriv,
		onData:   func([]byte, bool) { delivered <- struct{}{} },
	}

	sender := &Transfer{selfID: "sender"}
	innerBytes := sender.buildDecoyInner()

	var inner protocol.Packet
	if err := inner.UnmarshalBinary(innerBytes); err != nil {
		t.Fatal(err)
	}
	if !inner.Decoy {
		t.Fatal("decoy inner packet must have the Decoy flag set")
	}

	hops, err := toOnionHops([]routing.Hop{{NodeID: "dest", Address: "d:1", PubKey: dpub.Bytes()}})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := encryption.BuildOnion(hops, innerBytes)
	if err != nil {
		t.Fatal(err)
	}

	relayPkt := protocol.NewPacket(protocol.PacketTypeRelay, blob, "", "")
	dest.handleRelay(relayPkt)

	select {
	case <-delivered:
		t.Fatal("a decoy was delivered to the application")
	case <-time.After(200 * time.Millisecond):
		// not delivered — correct
	}
}

// TestPadPacket verifies padding grows a packet to the configured cell boundary
// and is a no-op when disabled.
func TestPadPacket(t *testing.T) {
	tr := &Transfer{padCell: 512}
	pkt := protocol.NewPacket(protocol.PacketTypeData, []byte("small"), "", "dest")
	tr.padPacket(pkt)
	if len(pkt.Pad) == 0 {
		t.Fatal("expected padding to be applied")
	}
	// Binary framing lets us hit the cell boundary exactly.
	if n := marshaledLen(pkt); n%512 != 0 {
		t.Fatalf("padded size = %d, want an exact multiple of 512", n)
	}

	// A larger payload pads to an exact larger multiple, never below its own size.
	big := protocol.NewPacket(protocol.PacketTypeData, make([]byte, 600), "", "dest")
	tr.padPacket(big)
	if n := marshaledLen(big); n%512 != 0 || n < 600 {
		t.Fatalf("padded size = %d, want an exact multiple of 512 >= payload", n)
	}

	// Disabled: no padding.
	off := &Transfer{padCell: 0}
	p2 := protocol.NewPacket(protocol.PacketTypeData, []byte("x"), "", "d")
	off.padPacket(p2)
	if len(p2.Pad) != 0 {
		t.Fatal("padding must be a no-op when padCell is 0")
	}
}
