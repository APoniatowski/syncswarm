package swarmsync

import (
	"bytes"
	"testing"
	"time"
)

// TestAutoRelayDelivery brings up AutoNAT-enabled nodes and verifies normal
// end-to-end delivery still works: on loopback every node is reachable, so
// AutoRelay must conclude reachable and NOT force reservations or break routing.
func TestAutoRelayDelivery(t *testing.T) {
	key := bytes.Repeat([]byte{0x71}, 32)
	payload := []byte("autonat-reachable-path")

	recv := make(chan []byte, 4)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, AutoRelay: true, OnDataReceived: func(b []byte) { recv <- b }})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2, AutoRelay: true})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	deliverBytesWithin(t, nodes, func() error { return sender.SendTo(payload, dest.NodeID()) }, recv, payload, 20*time.Second)
}
