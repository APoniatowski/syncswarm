package transfer

import (
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

// TestAck_IsPaddedLikeAFragment guards the traffic-analysis property that padding
// exists for in the first place.
//
// PadCellSize was applied to data fragments and decoys but not to acknowledgements,
// on any profile — including ProfileAnonymous, which sets it explicitly. An ack is
// far smaller than a fragment, so an unpadded one is identifiable by size alone: a
// reliable "this node just received something" marker leaving shortly after an
// inbound transfer, which is exactly the signal an observer needs to start
// correlating two endpoints. Padding the payload while leaving the receipt
// unpadded protects the message and advertises the conversation.
func TestAck_IsPaddedLikeAFragment(t *testing.T) {
	const cell = 512
	tr := &Transfer{padCell: cell}

	// An ack carries no payload, so unpadded it is far below one cell.
	ack := protocol.NewPacket(protocol.PacketTypeAcknowledgement, nil, "", "peer")
	bare, err := ack.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(bare)%cell == 0 {
		t.Skip("bare ack already lands on a cell boundary; test cannot distinguish")
	}

	tr.padPacket(ack)
	padded, err := ack.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(padded)%cell != 0 {
		t.Fatalf("padded ack is %d bytes, not a multiple of the %d-byte cell", len(padded), cell)
	}

	// And a fragment-sized packet must land on the same boundary, so the two are
	// not separable by size class.
	frag := protocol.NewPacket(protocol.PacketTypeData, make([]byte, 100), "", "peer")
	tr.padPacket(frag)
	fb, err := frag.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(fb)%cell != 0 {
		t.Fatalf("padded fragment is %d bytes, not a multiple of the cell", len(fb))
	}

	// With padding off, nothing is added — the cost stays opt-in.
	off := &Transfer{padCell: 0}
	plain := protocol.NewPacket(protocol.PacketTypeAcknowledgement, nil, "", "peer")
	off.padPacket(plain)
	if len(plain.Pad) != 0 {
		t.Fatalf("padding was applied with padCell=0 (%d bytes)", len(plain.Pad))
	}
}

// TestJitter_AppliesWhenConfigured guards the timing half of the same defence.
// Padding equalises what a packet looks like; jitter breaks *when* it appears.
// An acknowledgement emitted the instant a fragment lands pairs the two by timing
// regardless of size, so both matter — and both must stay opt-in, since a node
// that has not asked for anonymity should not pay latency for it.
func TestJitter_AppliesWhenConfigured(t *testing.T) {
	off := &Transfer{}
	off.ctx, off.cancel = testContext()
	defer off.cancel()
	start := time.Now()
	off.applyJitter()
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Fatalf("jitter delayed %v with relayJitter unset; it must cost nothing when off", elapsed)
	}

	on := &Transfer{relayJitter: 150 * time.Millisecond}
	on.ctx, on.cancel = testContext()
	defer on.cancel()

	// Sample several times: each delay is random in [0, relayJitter), so any single
	// draw can legitimately be tiny. What must hold is that delay is being applied
	// at all.
	var total time.Duration
	const samples = 8
	for i := 0; i < samples; i++ {
		s := time.Now()
		on.applyJitter()
		total += time.Since(s)
	}
	if total == 0 {
		t.Fatal("configured jitter produced no delay across any sample")
	}
	if avg := total / samples; avg > 150*time.Millisecond {
		t.Fatalf("average jitter %v exceeds the configured bound", avg)
	}
}
