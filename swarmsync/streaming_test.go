package swarmsync

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// testStreamSink captures a streamed transfer and signals the flushed bytes on
// Close.
type testStreamSink struct {
	buf  bytes.Buffer
	done chan []byte
}

func (s *testStreamSink) Write(p []byte) (int, error) { return s.buf.Write(p) }
func (s *testStreamSink) Close() error {
	out := append([]byte(nil), s.buf.Bytes()...)
	s.done <- out
	return nil
}

func streamUntil(t *testing.T, nodes []*SyncSwarm, send func() error, done <-chan []byte, want []byte, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(200 * time.Millisecond)
		if err := send(); err != nil {
			continue
		}
		select {
		case got := <-done:
			if !bytes.Equal(got, want) {
				t.Fatalf("streamed %d bytes, want %d", len(got), len(want))
			}
			return
		case <-time.After(1 * time.Second):
		}
	}
	t.Fatal("timed out waiting for streamed delivery")
}

// TestMultiNodeStreamedDelivery streams a payload over the forwarded (onion)
// path with a small block size (many blocks) and asserts the receiver's sink
// reassembles the exact bytes — bounded memory on both ends.
func TestMultiNodeStreamedDelivery(t *testing.T) {
	key := bytes.Repeat([]byte{0x51}, 32)
	payload := bytes.Repeat([]byte("streamed-over-relays-"), 6000) // ~126KB

	done := make(chan []byte, 8)
	mkSink := func(id [32]byte) io.WriteCloser { return &testStreamSink{done: done} }

	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnStreamReceived: mkSink})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2, StreamBlockSize: 16 * 1024})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	streamUntil(t, nodes, func() error { return sender.SendStream(bytes.NewReader(payload), dest.NodeID()) }, done, payload, 20*time.Second)
}

// TestDirectStreamedDelivery streams over a direct connection (no hops),
// exercising the streamed receive path with per-chunk acks.
func TestDirectStreamedDelivery(t *testing.T) {
	key := bytes.Repeat([]byte{0x52}, 32)
	payload := bytes.Repeat([]byte("direct-streamed-"), 4000) // ~64KB

	done := make(chan []byte, 8)
	mkSink := func(id [32]byte) io.WriteCloser { return &testStreamSink{done: done} }

	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnStreamReceived: mkSink})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, DataShards: 4, ParityShards: 2, StreamBlockSize: 8 * 1024})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	streamUntil(t, nodes, func() error { return sender.SendStream(bytes.NewReader(payload), dest.NodeID()) }, done, payload, 20*time.Second)
}

// TestStreamedFallbackToOnData verifies that without an OnStreamReceived sink, a
// streamed transfer is buffered and delivered via OnDataReceived.
func TestStreamedFallbackToOnData(t *testing.T) {
	key := bytes.Repeat([]byte{0x53}, 32)
	payload := bytes.Repeat([]byte("fallback-stream-"), 3000) // ~48KB

	recv := make(chan []byte, 8)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnDataReceived: func(b []byte) { recv <- b }})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, DataShards: 4, ParityShards: 2, StreamBlockSize: 8 * 1024})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	streamUntil(t, nodes, func() error { return sender.SendStream(bytes.NewReader(payload), dest.NodeID()) }, recv, payload, 20*time.Second)
}

// TestStreamForwardedFallsBackToDirect covers a swarm with hops configured but no
// third-party relay available (only the two endpoints). SendStream must fall back
// to a direct connection and still deliver, rather than committing to a forwarded
// route that cannot be built and silently black-holing the stream.
func TestStreamForwardedFallsBackToDirect(t *testing.T) {
	key := bytes.Repeat([]byte{0x60}, 32)
	payload := bytes.Repeat([]byte("no-relay-fallback-"), 4000) // ~72KB, multi-block

	done := make(chan []byte, 8)
	mkSink := func(id [32]byte) io.WriteCloser { return &testStreamSink{done: done} }

	// Only two nodes in the swarm; both relay-capable, but neither can relay to the
	// other (a relay must be distinct from the destination), so no forwarded route
	// exists even though HopCount is 1.
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnStreamReceived: mkSink})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, Relay: true, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2, StreamBlockSize: 16 * 1024})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	streamUntil(t, nodes, func() error { return sender.SendStream(bytes.NewReader(payload), dest.NodeID()) }, done, payload, 20*time.Second)
}

// TestStrictAnonymityErrorsWithoutRelay verifies that StrictAnonymity turns the
// silent anonymous->direct degradation into a hard error for both SendTo and
// SendStream when no relay route exists, so the sender is never revealed to the
// recipient behind its back.
func TestStrictAnonymityErrorsWithoutRelay(t *testing.T) {
	key := bytes.Repeat([]byte{0x61}, 32)

	recv := make(chan []byte, 8)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnDataReceived: func(b []byte) { recv <- b }})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, Relay: true, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2, StreamBlockSize: 16 * 1024, StrictAnonymity: true})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	// Let discovery settle so the destination is known (proving the error is about
	// the missing relay route, not an unknown destination).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(200 * time.Millisecond)
		if err := sender.SendTo([]byte("secret"), dest.NodeID()); err != nil {
			if !bytes.Contains([]byte(err.Error()), []byte("strict anonymity")) {
				continue // may still be "not active" until discovery settles
			}
			// SendStream must fail the same way.
			if serr := sender.SendStream(bytes.NewReader(bytes.Repeat([]byte("x"), 40000)), dest.NodeID()); serr == nil || !bytes.Contains([]byte(serr.Error()), []byte("strict anonymity")) {
				t.Fatalf("SendStream strict-anonymity error = %v, want strict-anonymity failure", serr)
			}
			return
		}
		t.Fatal("SendTo succeeded but strict anonymity should have blocked the direct fallback")
	}
	t.Fatal("timed out waiting for the destination to be discovered")
}

// TestStreamConfirmedDelivery verifies that with ConfirmDelivery, SendStream
// blocks until the receiver's end-to-end acknowledgement — returning nil only
// once the whole stream has been reassembled and flushed at the destination.
func TestStreamConfirmedDelivery(t *testing.T) {
	key := bytes.Repeat([]byte{0x5f}, 32)
	content := bytes.Repeat([]byte("confirmed-stream-block-"), 4000) // ~92 KB, multi-block

	done := make(chan []byte, 8)
	mkSink := func(id [32]byte) io.WriteCloser { return &testStreamSink{done: done} }

	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnStreamReceived: mkSink})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2, StreamBlockSize: 16 * 1024, ConfirmDelivery: true})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(300 * time.Millisecond)

		// With ConfirmDelivery, a nil return means the receiver acknowledged the
		// whole stream. An error means the route/ack wasn't ready — retry.
		if err := sender.SendStream(bytes.NewReader(content), dest.NodeID()); err != nil {
			continue
		}
		select {
		case got := <-done:
			if !bytes.Equal(got, content) {
				t.Fatalf("confirmed but wrong bytes: %d vs %d", len(got), len(content))
			}
			return
		case <-time.After(2 * time.Second):
			t.Fatal("SendStream confirmed but the sink never received the file")
		}
	}
	t.Fatal("timed out waiting for confirmed stream delivery")
}

// TestStreamSealedToRecipient proves per-recipient E2E for streamed files: the
// RECEIVER has no shared Key, so it can only reconstruct the stream by opening
// shards with its own node key — which only works if they were sealed to it.
func TestStreamSealedToRecipient(t *testing.T) {
	senderKey := bytes.Repeat([]byte{0x6e}, 32) // sender needs a key to enable RS config
	content := bytes.Repeat([]byte("sealed-stream-to-recipient-"), 4000)

	done := make(chan []byte, 8)
	mkSink := func(id [32]byte) io.WriteCloser { return &testStreamSink{done: done} }

	// Receiver: NO Key.
	dest := newTestNode(t, Options{NodeID: "dest", OnStreamReceived: mkSink})
	// Sender: has a key (enables erasure coding) + per-recipient sealing.
	sender := newTestNode(t, Options{NodeID: "sender", Key: senderKey, SealToRecipient: true, DataShards: 4, ParityShards: 2, StreamBlockSize: 16 * 1024})

	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(300 * time.Millisecond)

		if err := sender.SendStream(bytes.NewReader(content), dest.NodeID()); err != nil {
			continue
		}
		select {
		case got := <-done:
			if !bytes.Equal(got, content) {
				t.Fatalf("sealed stream mismatch: %d vs %d bytes", len(got), len(content))
			}
			return // success: opened with the node key alone => sealed to the recipient
		case <-time.After(2 * time.Second):
		}
	}
	t.Fatal("timed out waiting for sealed stream delivery")
}
