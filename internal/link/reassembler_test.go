package link

import (
	"encoding/binary"
	"testing"
	"time"
)

func chunkFrame(id0, id1 byte, idx, total uint16, payload []byte) []byte {
	f := make([]byte, msgHeaderLen+len(payload))
	f[0], f[1] = id0, id1
	binary.BigEndian.PutUint16(f[8:10], idx)
	binary.BigEndian.PutUint16(f[10:12], total)
	copy(f[msgHeaderLen:], payload)
	return f
}

// TestReassembler_StalePartialsDoNotWedgeTheLink covers a latent failure found
// while chasing the onion-over-Links streaming bug.
//
// The sub-protocols carried over a Link are explicitly best-effort, so a message
// whose chunks do not all arrive is an expected outcome, not an exception. But an
// incomplete partial was only ever removed by *completing*, and the table is
// capped — so once enough never-completing partials accumulated, the reassembler
// refused every subsequent message for the life of the link. A silent, permanent
// wedge with no error anywhere.
func TestReassembler_StalePartialsDoNotWedgeTheLink(t *testing.T) {
	var delivered int
	r := NewReassembler(func([]byte) { delivered++ })

	// Saturate with partials that will never complete: each claims two chunks and
	// sends only the first.
	for i := 0; i < maxInflightMessages; i++ {
		r.Feed(chunkFrame(byte(i), 0x01, 0, 2, []byte("a")))
	}

	// A well-formed, complete message must still get through.
	r.Feed(chunkFrame(0x00, 0x02, 0, 1, []byte("hello")))
	if delivered != 1 {
		t.Fatalf("delivered %d messages, want 1: a table full of partials that will "+
			"never complete permanently blocks every later message", delivered)
	}

	// Expired partials must be reclaimed rather than merely evicted under pressure.
	r2 := NewReassembler(func([]byte) {})
	r2.Feed(chunkFrame(0x11, 0x11, 0, 2, []byte("a")))
	r2.mu.Lock()
	for _, p := range r2.parts {
		p.started = time.Now().Add(-2 * partialTTL)
	}
	r2.mu.Unlock()

	// Fill to the cap, which sweeps expired entries on insert.
	for i := 0; i < maxInflightMessages; i++ {
		r2.Feed(chunkFrame(byte(i), 0x03, 0, 2, []byte("a")))
	}
	r2.mu.Lock()
	_, stale := r2.parts[[8]byte{0x11, 0x11}]
	n := len(r2.parts)
	r2.mu.Unlock()
	if stale {
		t.Error("an expired partial survived; entries must age out, not just be evicted")
	}
	if n > maxInflightMessages {
		t.Errorf("held %d partials, above the cap of %d", n, maxInflightMessages)
	}
}
