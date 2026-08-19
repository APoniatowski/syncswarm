package transfer

import (
	"bufio"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/routing"
)

// TestReservationForwarding proves a relay delivers to a reserved node over its
// held connection rather than dialing the node's (unreachable) address.
func TestReservationForwarding(t *testing.T) {
	_, relaySign, _ := ed25519.GenerateKey(nil)
	relay := &Transfer{
		selfID:       "relay",
		signKey:      relaySign,
		reservations: make(map[string]*reservedConn),
	}

	clientEnd, relayEnd := net.Pipe()
	defer clientEnd.Close()
	defer relayEnd.Close()

	// Register a held reservation for node "D".
	relay.reservations["D"] = &reservedConn{conn: relayEnd}

	got := make(chan *protocol.Packet, 1)
	go func() {
		pkt, err := protocol.ReadPacket(bufio.NewReader(clientEnd))
		if err != nil {
			got <- nil
			return
		}
		got <- pkt
	}()

	// The dial address is deliberately unreachable (TEST-NET-3): if the
	// reservation weren't used, this would fail rather than deliver.
	relay.forwardToNextHop("D", "203.0.113.1:1", []byte("onion-blob"))

	select {
	case pkt := <-got:
		if pkt == nil {
			t.Fatal("failed to read forwarded packet")
		}
		if pkt.Type != protocol.PacketTypeRelay {
			t.Fatalf("forwarded packet type = %d, want Relay", pkt.Type)
		}
		if string(pkt.Payload) != "onion-blob" {
			t.Fatalf("forwarded payload = %q, want the blob", pkt.Payload)
		}
		if pkt.SourceNode != "relay" || pkt.SignerID() != protocol.DeriveNodeID(relaySign.Public().(ed25519.PublicKey)) {
			t.Fatal("forwarded packet not signed/identified by the relay")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blob was not forwarded over the reservation")
	}

	// With no reservation for an unknown node, forwardToNextHop must not use the
	// held connection (it would dial instead).
	if relay.reservationFor("unknown") != nil {
		t.Fatal("reservationFor returned a connection for an unknown node")
	}
}

// TestPickReservationRelay checks the routing helper selects a relay the
// destination actually reserved with.
func TestPickReservationRelay(t *testing.T) {
	relays := []routing.Peer{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	if rr := pickReservationRelay(relays, []string{"x", "b"}); rr == nil || rr.ID != "b" {
		t.Fatalf("pickReservationRelay = %v, want b", rr)
	}
	if rr := pickReservationRelay(relays, []string{"z"}); rr != nil {
		t.Fatal("pickReservationRelay must return nil when none match")
	}
}
