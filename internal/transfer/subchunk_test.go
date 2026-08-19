package transfer

import (
	"bytes"
	"testing"

	"github.com/APoniatowski/syncswarm/internal/fragment"
	"github.com/APoniatowski/syncswarm/internal/protocol"
)

func TestFragmentPiecesSmallIsWhole(t *testing.T) {
	frag := fragment.Fragment{Index: 3, Total: 5, Payload: []byte("small")}
	pieces := fragmentPieces(frag, 1024)
	if len(pieces) != 1 {
		t.Fatalf("small fragment split into %d pieces, want 1", len(pieces))
	}
	p := pieces[0]
	if p.SubTotal != 1 || p.SubIndex != 0 {
		t.Fatalf("whole fragment must have SubIndex=0 SubTotal=1, got %d/%d", p.SubIndex, p.SubTotal)
	}
	if !bytes.Equal(p.Payload, frag.Payload) || p.Index != 3 || p.Total != 5 {
		t.Fatal("whole fragment must preserve payload, index, and total")
	}
}

func TestFragmentPiecesSplitsAndReassembles(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdefghij"), 100) // 1000 bytes
	frag := fragment.Fragment{Index: 2, Total: 4, Payload: payload}
	const size = 256
	pieces := fragmentPieces(frag, size)

	want := (len(payload) + size - 1) / size
	if len(pieces) != want {
		t.Fatalf("split into %d pieces, want %d", len(pieces), want)
	}

	var got []byte
	for i, p := range pieces {
		if p.Index != 2 || p.Total != 4 {
			t.Fatalf("piece %d lost logical index/total: %d/%d", i, p.Index, p.Total)
		}
		if int(p.SubIndex) != i || int(p.SubTotal) != want {
			t.Fatalf("piece %d has SubIndex/SubTotal %d/%d, want %d/%d", i, p.SubIndex, p.SubTotal, i, want)
		}
		if len(p.Payload) > size {
			t.Fatalf("piece %d exceeds sub-chunk size: %d > %d", i, len(p.Payload), size)
		}
		got = append(got, p.Payload...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reassembled sub-chunks must equal the original fragment payload")
	}
}

func newSubState() *transferState {
	return &transferState{
		Received: make(map[uint32]bool),
		Chunks:   make(map[uint32][]byte),
	}
}

func pkt(idx, subIdx, subTotal uint32, payload string) *protocol.Packet {
	return &protocol.Packet{ChunkNumber: idx, SubIndex: subIdx, SubTotal: subTotal, Payload: []byte(payload)}
}

func TestAbsorbWholeFragment(t *testing.T) {
	st := newSubState()
	idx, payload, ok := absorbFragmentPieceLocked(st, pkt(0, 0, 1, "hello"))
	if !ok || idx != 0 || string(payload) != "hello" {
		t.Fatalf("a whole fragment must complete immediately: ok=%v idx=%d payload=%q", ok, idx, payload)
	}
}

func TestAbsorbSubChunksOutOfOrder(t *testing.T) {
	st := newSubState()

	// Deliver 3 sub-chunks of fragment 7 out of order.
	if _, _, ok := absorbFragmentPieceLocked(st, pkt(7, 2, 3, "GHI")); ok {
		t.Fatal("must not complete with 1 of 3 sub-chunks")
	}
	if _, _, ok := absorbFragmentPieceLocked(st, pkt(7, 0, 3, "ABC")); ok {
		t.Fatal("must not complete with 2 of 3 sub-chunks")
	}
	idx, payload, ok := absorbFragmentPieceLocked(st, pkt(7, 1, 3, "DEF"))
	if !ok {
		t.Fatal("must complete once all 3 sub-chunks arrive")
	}
	if idx != 7 || string(payload) != "ABCDEFGHI" {
		t.Fatalf("reassembled in wrong order: idx=%d payload=%q", idx, payload)
	}
}

func TestAbsorbDuplicateSubChunkIgnored(t *testing.T) {
	st := newSubState()
	absorbFragmentPieceLocked(st, pkt(1, 0, 2, "AA"))
	// Duplicate of sub-chunk 0 must not count as the missing sub-chunk 1.
	if _, _, ok := absorbFragmentPieceLocked(st, pkt(1, 0, 2, "AA")); ok {
		t.Fatal("a duplicate sub-chunk must not complete the fragment")
	}
	if _, payload, ok := absorbFragmentPieceLocked(st, pkt(1, 1, 2, "BB")); !ok || string(payload) != "AABB" {
		t.Fatalf("distinct final sub-chunk must complete: ok=%v payload=%q", ok, payload)
	}
}

func TestAbsorbRejectsOutOfRangeSubIndex(t *testing.T) {
	st := newSubState()
	if _, _, ok := absorbFragmentPieceLocked(st, pkt(0, 5, 3, "X")); ok {
		t.Fatal("a sub-chunk index >= SubTotal must be rejected")
	}
}

func TestAbsorbSkipsAlreadyReceived(t *testing.T) {
	st := newSubState()
	st.Received[4] = true
	if _, _, ok := absorbFragmentPieceLocked(st, pkt(4, 0, 1, "late")); ok {
		t.Fatal("a fragment already fully received must not be re-absorbed")
	}
}
