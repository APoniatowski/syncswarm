package swarmsync

import (
	"bytes"
	"testing"
	"time"
)

// TestSealToRecipientNoSharedKey proves per-recipient E2E: with NO shared Key on
// either node, a message still delivers and decrypts — which is only possible if
// it was sealed to the recipient's public key and opened with its node key.
func TestSealToRecipientNoSharedKey(t *testing.T) {
	payload := []byte("sealed to the recipient's key alone")
	recv := make(chan []byte, 4)

	// No Key set on either side.
	dest := newTestNode(t, Options{NodeID: "dest", OnDataReceived: func(b []byte) { recv <- b }})
	sender := newTestNode(t, Options{NodeID: "sender", SealToRecipient: true})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	deliverBytesWithin(t, nodes, func() error { return sender.SendTo(payload, dest.NodeID()) }, recv, payload, 20*time.Second)
}

// TestSealToRecipientWithErasureCoding: recipient-key sealing also works through
// the Reed-Solomon path (a shared Key enables RS; targeted sends still seal each
// shard to the recipient).
func TestSealToRecipientWithErasureCoding(t *testing.T) {
	key := bytes.Repeat([]byte{0x2b}, 32)
	payload := bytes.Repeat([]byte("sealed-and-erasure-coded-"), 300)
	recv := make(chan []byte, 4)

	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnDataReceived: func(b []byte) { recv <- b }})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, SealToRecipient: true, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	deliverBytesWithin(t, nodes, func() error { return sender.SendTo(payload, dest.NodeID()) }, recv, payload, 20*time.Second)
}

// TestSealToRecipientPostQuantum proves post-quantum per-recipient E2E: with no
// shared Key, the sender seals with hybrid X25519 + ML-KEM-768 to the receiver's
// advertised keys, and the receiver opens with its own — delivery is only
// possible through the PQ hybrid path.
func TestSealToRecipientPostQuantum(t *testing.T) {
	payload := []byte("harvest-now-decrypt-later? not this one")
	recv := make(chan []byte, 4)

	// Receiver advertises an ML-KEM key (PostQuantum) and can open PQ-sealed data.
	dest := newTestNode(t, Options{NodeID: "dest", PostQuantum: true, OnDataReceived: func(b []byte) { recv <- b }})
	// Sender seals to the recipient using the PQ hybrid.
	sender := newTestNode(t, Options{NodeID: "sender", SealToRecipient: true, PostQuantum: true})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	deliverBytesWithin(t, nodes, func() error { return sender.SendTo(payload, dest.NodeID()) }, recv, payload, 20*time.Second)
}
