package protocol

import (
	"bytes"
	"testing"
)

// TestSubChunkCodecRoundTrip verifies the sub-chunk position fields survive the
// binary codec.
func TestSubChunkCodecRoundTrip(t *testing.T) {
	p := NewPacket(PacketTypeData, []byte("payload-bytes"), "grp", "dst")
	p.ChunkNumber = 2
	p.TotalChunks = 6
	p.SubIndex = 3
	p.SubTotal = 7
	p.DataShards = 4
	p.ParityShards = 2
	p.OriginalLen = 12345

	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var q Packet
	if err := q.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if q.SubIndex != 3 || q.SubTotal != 7 || q.ChunkNumber != 2 || q.TotalChunks != 6 || q.DataShards != 4 || q.OriginalLen != 12345 {
		t.Fatalf("codec mismatch: sub=%d/%d chunk=%d/%d ds=%d ol=%d", q.SubIndex, q.SubTotal, q.ChunkNumber, q.TotalChunks, q.DataShards, q.OriginalLen)
	}
}

// TestNewPacketDoesNotMutateAliasedPayload guards the sub-chunk corruption bug:
// NewPacket must not append into the caller's payload backing array, which would
// clobber a neighbouring sub-chunk that shares the same underlying buffer.
func TestNewPacketDoesNotMutateAliasedPayload(t *testing.T) {
	backing := make([]byte, 20)
	for i := range backing {
		backing[i] = byte('A' + i)
	}
	first := backing[0:10]                         // sub-slice with capacity into the rest
	next := append([]byte(nil), backing[10:20]...) // snapshot of the "next sub-chunk"

	_ = NewPacket(PacketTypeData, first, "", "")

	if !bytes.Equal(backing[10:20], next) {
		t.Fatalf("NewPacket mutated bytes past the payload: got %q want %q", backing[10:20], next)
	}
}
