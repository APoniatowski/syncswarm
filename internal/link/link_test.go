package link

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// pair wires two managers so each one's send delivers into the other's Deliver
// (asynchronously, as a real transport would), and returns them with the
// destination's public key.
func pair(t *testing.T) (a, b *Manager, bPub ed25519.PublicKey) {
	t.Helper()
	_, aPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bPub, bPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(to *Manager, from string) SendFunc {
		return func(_ string, frame []byte) error {
			var pkt protocol.Packet
			if err := pkt.UnmarshalBinary(frame); err != nil {
				return err
			}
			go to.Deliver(from, &pkt)
			return nil
		}
	}
	a = NewManager(aPriv, nil)
	b = NewManager(bPriv, nil)
	a.send = deliver(b, "A")
	b.send = deliver(a, "B")
	return a, b, bPub
}

func TestLink_EstablishAndExchange(t *testing.T) {
	a, b, bPub := pair(t)

	linkReady := make(chan *Link, 1)
	recvB := make(chan []byte, 1)
	b.OnInboundLink(func(l *Link) {
		l.OnData(func(d []byte) { recvB <- d })
		linkReady <- l
	})

	la, err := a.Dial("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// A -> B
	if err := la.Send([]byte("hello from A")); err != nil {
		t.Fatalf("send A->B: %v", err)
	}
	select {
	case got := <-recvB:
		if !bytes.Equal(got, []byte("hello from A")) {
			t.Fatalf("B received %q, want %q", got, "hello from A")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("B never received A's data")
	}

	// B -> A (proves the shared key works in both directions)
	lb := <-linkReady
	recvA := make(chan []byte, 1)
	la.OnData(func(d []byte) { recvA <- d })
	if err := lb.Send([]byte("hello from B")); err != nil {
		t.Fatalf("send B->A: %v", err)
	}
	select {
	case got := <-recvA:
		if !bytes.Equal(got, []byte("hello from B")) {
			t.Fatalf("A received %q, want %q", got, "hello from B")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("A never received B's data")
	}
}

func TestLink_WrongDestinationKeyRejected(t *testing.T) {
	a, _, _ := pair(t)
	// Dial B but verify against an unrelated key: the proof signature must fail,
	// so the handshake never completes.
	wrongPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Dial("B", wrongPub, 500*time.Millisecond); err == nil {
		t.Fatal("handshake succeeded with the wrong destination key")
	}
}

func TestLink_ForgedDataRejected(t *testing.T) {
	a, b, bPub := pair(t)
	b.OnInboundLink(func(l *Link) {
		l.OnData(func([]byte) { t.Error("forged frame was decrypted and delivered") })
	})
	la, err := a.Dial("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Hand B a LinkData for this link with a bogus ciphertext: AEAD open must fail
	// and no data reach the application.
	forged, _ := marshalTestData(dataPayload{
		LinkID: la.ID,
		Nonce:  make([]byte, 12),
		Cipher: []byte("not a valid ciphertext"),
	})
	b.Deliver("A", forged)
	time.Sleep(100 * time.Millisecond) // give any (erroneous) delivery a chance to fire
}

func marshalTestData(d dataPayload) (*protocol.Packet, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return protocol.NewPacket(protocol.PacketTypeLinkData, data, "ANY", ""), nil
}
