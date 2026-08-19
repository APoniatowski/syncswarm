package swarmsync

import (
	"bytes"
	"testing"
	"time"
)

// TestDirectSubChunkedDelivery is the non-forwarded complement to
// TestMultiNodeSubChunkedDelivery: a directly-addressed RS transfer whose shards
// are split into sub-chunks (SubChunkSize below the shard size) must still
// reassemble exactly, exercising sub-chunk reassembly on the streamed path.
func TestDirectSubChunkedDelivery(t *testing.T) {
	key := bytes.Repeat([]byte{0x3d}, 32)
	payload := bytes.Repeat([]byte("direct-subchunk-"), 3000) // ~48KB

	recv := make(chan []byte, 4)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnDataReceived: func(b []byte) { recv <- b }})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, DataShards: 4, ParityShards: 2, SubChunkSize: 4096})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	deliverBytesWithin(t, nodes, func() error { return sender.SendTo(payload, dest.NodeID()) }, recv, payload, 15*time.Second)
}
