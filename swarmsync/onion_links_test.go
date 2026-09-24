package swarmsync

import (
	"bytes"
	"testing"
	"time"
)

// TestOnionOverLinks sends an onion-routed (HopCount=1) transfer with
// OnionOverLinks enabled, so each hop rides an encrypted Link instead of a direct
// TCP dial: sender → relay → dest. The destination must receive the exact bytes,
// proving the Phase 0b.3 onion-over-Links forward and receive paths work end to end
// (the relay peels one layer and forwards the remainder over a Link to the dest).
func TestOnionOverLinks(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	recv := make(chan []byte, 4)

	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnionOverLinks: true,
		OnDataReceived: func(b []byte) { recv <- b }})
	relay := newTestNode(t, Options{NodeID: "relay", Key: key, Relay: true, OnionOverLinks: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1,
		DataShards: 4, ParityShards: 2, OnionOverLinks: true})

	nodes := []*SyncSwarm{dest, relay, sender}
	wireAndStart(t, nodes...)

	payload := []byte("anonymous onion payload carried hop-by-hop over encrypted links")
	deliverBytesWithin(t, nodes, func() error {
		return sender.SendTo(payload, dest.NodeID())
	}, recv, payload, 25*time.Second)
}
