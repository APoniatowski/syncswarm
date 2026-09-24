package link

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lossyPipe wires a ResourceSender and ResourceReceiver together in memory,
// dropping a fraction of frames in each direction to exercise ARQ. Frames are
// delivered on buffered channels by pump goroutines so a send never re-enters the
// peer synchronously.
type lossyPipe struct {
	toRecv, toSend chan []byte
	stopped        chan struct{}
	once           sync.Once
	dropRate       float64
	rng            *rand.Rand
	rngMu          sync.Mutex
	sent           atomic.Int64 // frames the sender emitted (incl. retransmits)
}

func newLossyPipe(dropRate float64, seed int64) *lossyPipe {
	return &lossyPipe{
		toRecv:   make(chan []byte, 4096),
		toSend:   make(chan []byte, 4096),
		stopped:  make(chan struct{}),
		dropRate: dropRate,
		rng:      rand.New(rand.NewSource(seed)),
	}
}

func (p *lossyPipe) drop() bool {
	p.rngMu.Lock()
	defer p.rngMu.Unlock()
	return p.rng.Float64() < p.dropRate
}

func (p *lossyPipe) senderSend(f []byte) error {
	p.sent.Add(1)
	if p.drop() {
		return nil
	}
	cp := append([]byte(nil), f...)
	select {
	case p.toRecv <- cp:
	case <-p.stopped:
	}
	return nil
}

func (p *lossyPipe) receiverSend(f []byte) error {
	if p.drop() {
		return nil
	}
	cp := append([]byte(nil), f...)
	select {
	case p.toSend <- cp:
	case <-p.stopped:
	}
	return nil
}

func (p *lossyPipe) run(s *ResourceSender, r *ResourceReceiver) {
	go func() {
		for {
			select {
			case f := <-p.toRecv:
				r.Feed(f)
			case <-p.stopped:
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case f := <-p.toSend:
				s.Feed(f)
			case <-p.stopped:
				return
			}
		}
	}()
}

func (p *lossyPipe) stop() { p.once.Do(func() { close(p.stopped) }) }

func runResource(t *testing.T, payload []byte, partSize int, dropRate float64, seed int64) (got []byte, senderFrames int64) {
	t.Helper()
	pipe := newLossyPipe(dropRate, seed)
	defer pipe.stop()

	var (
		mu   sync.Mutex
		done = make(chan struct{})
	)
	recv := NewResourceReceiver(pipe.receiverSend, func(_ [16]byte, data []byte) {
		mu.Lock()
		got = append([]byte(nil), data...)
		mu.Unlock()
		close(done)
	})

	// 100ms RTO, not 20ms: the retransmit loop sweeps once per tick, and a 20ms
	// tick meant ~50 sweeps/second per transfer. Isolated that is fine, but when
	// `go test ./...` runs packages concurrently this test gets starved of CPU and
	// misses its deadline — a flaky failure that says nothing about the ARQ. Still
	// well under the 250ms production default, so convergence stays quick.
	s, err := NewResourceSender(payload, partSize, 16, 100*time.Millisecond, pipe.senderSend)
	if err != nil {
		t.Fatal(err)
	}
	pipe.run(s, recv)
	s.Start()

	// Deliberately generous. These tests assert a *reliability* property — the
	// transfer completes despite loss — not a latency one. Isolated they finish in
	// under a second (~6s under -race); but `go test ./...` runs packages
	// concurrently, and under that contention a tight wall-clock bound tests the
	// scheduler rather than the ARQ. The deadline is only a liveness backstop, so
	// a genuinely stuck transfer still fails instead of hanging forever.
	if err := s.Wait(60 * time.Second); err != nil {
		// Report where the ARQ actually got to. This test has intermittently
		// exceeded its deadline under heavy parallel load, and it is not yet
		// established whether that is pure CPU starvation or a rare livelock in the
		// Resource layer — so capture the state rather than leaving the next
		// failure opaque. A base that is far from total with most parts acked
		// points at lost-wakeup/bookkeeping; a base that simply crawled points at
		// starvation.
		s.mu.Lock()
		acked := 0
		for _, a := range s.acked {
			if a {
				acked++
			}
		}
		base, sentHigh, total := s.base, s.sentHigh, len(s.parts)
		s.mu.Unlock()
		t.Fatalf("sender: %v (progress: base=%d/%d acked=%d sentHigh=%d, frames emitted=%d)",
			err, base, total, acked, sentHigh, pipe.sent.Load())
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver never completed after sender finished")
	}
	mu.Lock()
	defer mu.Unlock()
	return got, pipe.sent.Load()
}

func TestResource_ReliableNoLoss(t *testing.T) {
	for _, payload := range [][]byte{
		{},
		[]byte("one part"),
		bytes.Repeat([]byte("abcdefghij"), 500), // ~5000 bytes, many parts
	} {
		got, _ := runResource(t, payload, 50, 0, 1)
		if !bytes.Equal(got, payload) {
			t.Fatalf("no-loss: reassembled %d bytes, want %d", len(got), len(payload))
		}
	}
}

func TestResource_RecoversFromLoss(t *testing.T) {
	payload := bytes.Repeat([]byte("The quick brown fox. "), 400) // ~8400 bytes
	const partSize = 50
	totalParts := (len(payload) + partSize - 1) / partSize

	got, frames := runResource(t, payload, partSize, 0.30, 42)
	if !bytes.Equal(got, payload) {
		t.Fatalf("lossy: reassembled %d bytes, want %d", len(got), len(payload))
	}
	// ARQ must have retransmitted (more frames than parts) but stay bounded — not
	// an unbounded resend storm.
	if frames <= int64(totalParts) {
		t.Fatalf("expected retransmissions over a lossy link; sent %d frames for %d parts", frames, totalParts)
	}
	if frames > int64(totalParts)*10 {
		t.Fatalf("resend storm: %d frames for %d parts", frames, totalParts)
	}
}

func TestResource_HeavyTailLoss(t *testing.T) {
	// A different seed / higher loss still completes (tail-loss recovered by RTO,
	// not just selective ACK).
	payload := bytes.Repeat([]byte("payload-"), 300)
	got, _ := runResource(t, payload, 40, 0.5, 7)
	if !bytes.Equal(got, payload) {
		t.Fatalf("heavy loss: reassembled %d bytes, want %d", len(got), len(payload))
	}
}

// TestResource_AdvertisementBoundsAllocation is the guard for the worst
// amplification found in the project-wide audit. A resource advertisement is a
// peer's *claim* about a transfer it has not sent, and the receiver sized two
// slices directly from it. A single frame declaring total=2^32-1 asked for roughly
// 100 GB of slice headers — an OOM kill for a few dozen bytes, from any peer able
// to establish a link.
func TestResource_AdvertisementBoundsAllocation(t *testing.T) {
	var id [16]byte
	var whole [32]byte

	r := NewResourceReceiver(func([]byte) error { return nil }, func([16]byte, []byte) {})

	// The extreme claim must be discarded without allocating from it.
	r.Feed(encodeAdv(id, ^uint32(0), 1, whole))
	if n := r.pending(); n != 0 {
		t.Fatalf("receiver accepted an advertisement of %d parts (state entries: %d)", ^uint32(0), n)
	}

	// Just over the cap is refused too, so the bound is the bound.
	r.Feed(encodeAdv(id, uint32(maxResourceParts)+1, 1, whole))
	if n := r.pending(); n != 0 {
		t.Fatalf("receiver accepted %d parts, above the cap of %d", maxResourceParts+1, maxResourceParts)
	}

	// A claim whose parts are individually fine but whose total size is absurd is
	// also refused: the product is what determines the memory, not either factor.
	r.Feed(encodeAdv(id, uint32(maxResourceParts), maxResourcePartSize, whole))
	if n := r.pending(); n != 0 {
		t.Fatal("receiver accepted an advertisement implying a multi-terabyte resource")
	}

	// And an ordinary advertisement still works, or the bound has broken transfers.
	r.Feed(encodeAdv(id, 4, 1024, whole))
	if n := r.pending(); n != 1 {
		t.Fatalf("a legitimate advertisement was rejected (state entries: %d)", n)
	}
}

// TestResource_CompletionAckLossDoesNotDeadlock reproduces the ARQ stall that had
// been written off as test slowness.
//
// On completion the receiver deletes its state and sends a final ack plus DONE. If
// both are lost, the sender's retransmits arrive at a receiver with nothing to
// match them against — and it answered with silence, so the sender retried until
// its deadline. Two dropped frames stall a transfer permanently, and an adversary
// able to drop them can pin a sender's resources for its whole timeout.
//
// The pipe drops the completing ack and the first DONE exactly once, which is that
// transient loss made deterministic. Recovery must then come from the receiver
// answering a later retransmit.
func TestResource_CompletionAckLossDoesNotDeadlock(t *testing.T) {
	payload := bytes.Repeat([]byte("payload."), 64) // 512 bytes, several parts
	const partSize = 64
	total := (len(payload) + partSize - 1) / partSize

	var (
		mu          sync.Mutex
		completed   bool
		droppedAck  bool
		droppedDone bool
		sender      *ResourceSender
	)

	recv := NewResourceReceiver(func(f []byte) error {
		mu.Lock()
		switch {
		case f[0] == resTagAck && int(binary.BigEndian.Uint32(f[1+resIDLen:])) >= total && !droppedAck:
			droppedAck = true // lose the ack that would have completed the transfer
			mu.Unlock()
			return nil
		case f[0] == resTagDone && !droppedDone:
			droppedDone = true // and lose the DONE that follows it
			mu.Unlock()
			return nil
		}
		mu.Unlock()
		if sender != nil {
			sender.Feed(f)
		}
		return nil
	}, func(_ [16]byte, _ []byte) {
		mu.Lock()
		completed = true
		mu.Unlock()
	})

	s, err := NewResourceSender(payload, partSize, 4, 50*time.Millisecond, func(f []byte) error {
		recv.Feed(f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sender = s

	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = s.Wait(6 * time.Second)
		close(done)
	}()
	s.Start()

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("sender never returned from Wait")
	}

	mu.Lock()
	gotCompleted, gotAck, gotDone := completed, droppedAck, droppedDone
	mu.Unlock()
	if !gotCompleted {
		t.Fatal("receiver never completed the resource")
	}
	if !gotAck || !gotDone {
		t.Fatalf("test did not exercise the loss it is about (ack dropped: %v, done dropped: %v)",
			gotAck, gotDone)
	}
	if waitErr != nil {
		t.Fatalf("sender stalled after the completing ack and DONE were lost (%v): a "+
			"retransmit reaching a finished receiver must be answered, not ignored", waitErr)
	}
}
