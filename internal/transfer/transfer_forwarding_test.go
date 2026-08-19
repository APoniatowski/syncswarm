package transfer

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/fragment"
	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/routing"
)

// TestForwardedDeliveryRoundTrip drives the whole multi-hop path in-process
// (no sockets): the sender seals fragments and wraps each in per-hop layers;
// each relay peels exactly one layer and hands the inner blob onward; the final
// node peels the last layer, reassembles, and delivers the original bytes.
func TestForwardedDeliveryRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	sealer, err := encryption.NewAEADSealer(key)
	if err != nil {
		t.Fatal(err)
	}

	// Two relays + destination, each with its own X25519 identity.
	r1priv, r1pub, _ := encryption.GenerateX25519KeyPair()
	r2priv, r2pub, _ := encryption.GenerateX25519KeyPair()
	dpriv, dpub, _ := encryption.GenerateX25519KeyPair()

	onionHops, err := toOnionHops([]routing.Hop{
		{NodeID: "r1", Address: "r1:1", PubKey: r1pub.Bytes()},
		{NodeID: "r2", Address: "r2:1", PubKey: r2pub.Bytes()},
		{NodeID: "dest", Address: "d:1", PubKey: dpub.Bytes()},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Small chunk size so the payload spans many fragments.
	id := sha256.Sum256([]byte("transfer-id"))
	data := bytes.Repeat([]byte("syncswarm-forwarding-"), 400)
	fr, err := fragment.NewFragmenter(sealer, 64)
	if err != nil {
		t.Fatal(err)
	}
	frags, err := fr.Fragment(id, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frags))
	}

	// Forwarded inner packets are deliberately anonymous (unsigned, no
	// SourceNode); the onion's final-layer AEAD authenticates them.
	sender := &Transfer{selfID: "sender", sealer: sealer}
	done := make(chan []byte, 1)
	dest := &Transfer{selfID: "dest", sealer: sealer, nodePriv: dpriv, onData: func(b []byte, _ bool) { done <- b }}

	for _, frag := range frags {
		inner, err := sender.buildInnerFragment(id, "dest", frag, scheme{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := encryption.BuildOnion(onionHops, inner)
		if err != nil {
			t.Fatal(err)
		}

		// Hop 1 (r1): peels, learns only that the next hop is r2.
		p1, err := encryption.PeelOnion(r1priv, blob)
		if err != nil || p1.IsFinal || p1.NextNode != "r2" {
			t.Fatalf("r1 peel: err=%v final=%v next=%q", err, p1.IsFinal, p1.NextNode)
		}
		// Hop 2 (r2): peels, next is dest.
		p2, err := encryption.PeelOnion(r2priv, p1.Inner)
		if err != nil || p2.IsFinal || p2.NextNode != "dest" {
			t.Fatalf("r2 peel: err=%v final=%v next=%q", err, p2.IsFinal, p2.NextNode)
		}
		// Hop 3 (dest): final layer yields the inner data packet.
		p3, err := encryption.PeelOnion(dpriv, p2.Inner)
		if err != nil || !p3.IsFinal {
			t.Fatalf("dest peel: err=%v final=%v", err, p3.IsFinal)
		}

		var innerPkt protocol.Packet
		if err := innerPkt.UnmarshalBinary(p3.Inner); err != nil {
			t.Fatal(err)
		}
		// Inner packets are anonymous/unsigned; the onion peel above already
		// authenticated the bytes.
		dest.ingestForwardedFragment(&innerPkt)
	}

	select {
	case got := <-done:
		if !bytes.Equal(got, data) {
			t.Fatalf("delivered %d bytes, want %d", len(got), len(data))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for forwarded delivery")
	}
}

func TestRotatePeers(t *testing.T) {
	peers := []routing.Peer{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	got := rotatePeers(peers, 1)
	if got[0].ID != "b" || got[1].ID != "c" || got[2].ID != "a" {
		t.Fatalf("rotate by 1 = %s,%s,%s", got[0].ID, got[1].ID, got[2].ID)
	}
	// Rotation must not mutate the input.
	if peers[0].ID != "a" {
		t.Fatal("rotatePeers mutated its input")
	}
	// Wrap-around and zero cases.
	if r := rotatePeers(peers, 3); r[0].ID != "a" {
		t.Fatalf("rotate by len = %s, want a", r[0].ID)
	}
	if r := rotatePeers(nil, 2); r != nil {
		t.Fatal("rotate of nil should be nil")
	}
}

// TestReplyBlockAnonymousAck verifies a sender-built reply block routes an ack
// back through a relay to the sender, and that the ack carries no sender identity.
func TestReplyBlockAnonymousAck(t *testing.T) {
	senderPriv, _, _ := encryption.GenerateX25519KeyPair()
	sender := &Transfer{selfID: "sender", nodePriv: senderPriv, hopCount: 1, selfHost: "127.0.0.1", dataPort: 5000}

	rPriv, rPub, _ := encryption.GenerateX25519KeyPair()
	relays := []routing.Peer{{ID: "r", Address: "127.0.0.1:6000", PubKey: rPub.Bytes(), Active: true, RelayCapable: true}}

	id := sha256.Sum256([]byte("reply"))
	token := []byte("secret-ack-token")
	rbBytes := sender.buildReplyBlock(id, relays, token)
	if rbBytes == nil {
		t.Fatal("expected a reply block to be built")
	}
	var rb replyBlock
	if err := json.Unmarshal(rbBytes, &rb); err != nil {
		t.Fatal(err)
	}
	if rb.EntryAddr != "127.0.0.1:6000" {
		t.Fatalf("entry addr = %q, want the relay", rb.EntryAddr)
	}

	// Relay peels its layer and forwards toward the sender's own address.
	p1, err := encryption.PeelOnion(rPriv, rb.Blob)
	if err != nil || p1.IsFinal {
		t.Fatalf("relay peel: err=%v final=%v", err, p1.IsFinal)
	}
	if p1.NextAddr != "127.0.0.1:5000" {
		t.Fatalf("relay next hop = %q, want the sender", p1.NextAddr)
	}
	// Sender peels the final layer and recovers the ack.
	p2, err := encryption.PeelOnion(senderPriv, p1.Inner)
	if err != nil || !p2.IsFinal {
		t.Fatalf("sender peel: err=%v final=%v", err, p2.IsFinal)
	}
	var ack protocol.Packet
	if err := ack.UnmarshalBinary(p2.Inner); err != nil {
		t.Fatal(err)
	}
	if ack.Type != protocol.PacketTypeAcknowledgement || ack.ID != id {
		t.Fatalf("recovered wrong ack: type=%d id-match=%v", ack.Type, ack.ID == id)
	}
	if ack.SourceNode != "" || len(ack.SignerKey) != 0 {
		t.Fatal("anonymous ack must carry no source identity")
	}
	// The ack must echo the secret token so the sender can authenticate it.
	if string(ack.Payload) != string(token) {
		t.Fatalf("ack token = %q, want %q", ack.Payload, token)
	}

	// With no relays, a reply block would expose the sender directly, so none is built.
	if sender.buildReplyBlock(id, nil, token) != nil {
		t.Fatal("must not build a zero-relay reply block")
	}
}

// TestInnerFragmentIsAnonymous asserts forwarded data packets leak no sender.
func TestInnerFragmentIsAnonymous(t *testing.T) {
	sender := &Transfer{selfID: "sender", signKey: nil}
	id := sha256.Sum256([]byte("x"))
	frag := fragment.Fragment{TransferID: id, Index: 0, Total: 1, Payload: []byte("p")}
	b, err := sender.buildInnerFragment(id, "dest", frag, scheme{}, []byte("rb"))
	if err != nil {
		t.Fatal(err)
	}
	var pkt protocol.Packet
	if err := pkt.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if pkt.SourceNode != "" {
		t.Fatal("inner packet leaks SourceNode")
	}
	if len(pkt.SignerKey) != 0 || len(pkt.Signature) != 0 {
		t.Fatal("inner packet is identity-signed, leaking the sender")
	}
	if string(pkt.ReplyBlock) != "rb" {
		t.Fatal("reply block not carried")
	}
}

// TestAckAuthentication verifies forged acks cannot stop a sender's resends:
// direct acks must carry the expected destination key, forwarded acks the token.
func TestAckAuthentication(t *testing.T) {
	tr := &Transfer{pendingAcks: make(map[[32]byte]*pendingAck)}
	destKey := []byte("expected-destination-ed25519-key")
	token := []byte("per-transfer-secret")

	// Forwarded transfer: authenticated by token.
	id := sha256.Sum256([]byte("fwd"))
	ch := tr.registerAck(id, destKey, token)
	tr.signalAckFrom(id, []byte("attacker-key")) // wrong: direct ack from a forger
	tr.signalAckToken(id, []byte("wrong-token")) // wrong: bad token
	select {
	case <-ch:
		t.Fatal("forged ack accepted for forwarded transfer")
	default:
	}
	tr.signalAckToken(id, token) // correct token
	select {
	case <-ch:
	default:
		t.Fatal("valid token ack not accepted")
	}

	// Direct transfer: authenticated by destination key.
	id2 := sha256.Sum256([]byte("direct"))
	ch2 := tr.registerAck(id2, destKey, nil)
	tr.signalAckToken(id2, token)              // wrong path (no token registered)
	tr.signalAckFrom(id2, []byte("other-key")) // wrong key
	select {
	case <-ch2:
		t.Fatal("forged ack accepted for direct transfer")
	default:
	}
	tr.signalAckFrom(id2, destKey) // correct destination key
	select {
	case <-ch2:
	default:
		t.Fatal("valid direct ack not accepted")
	}
}
