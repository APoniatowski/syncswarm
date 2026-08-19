package transfer

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/fragment"
	"github.com/APoniatowski/syncswarm/internal/protocol"
)

type captureSink struct {
	buf    bytes.Buffer
	closed bool
}

func (c *captureSink) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *captureSink) Close() error                { c.closed = true; return nil }

// streamRoundTrip encodes data through the streaming send pipeline into wire
// packets, optionally reorders them, feeds them into a fresh assembler, and
// returns the flushed bytes and whether the sink was closed.
func streamRoundTrip(t *testing.T, tr *Transfer, data []byte, reorder func([]*protocol.Packet)) ([]byte, bool) {
	t.Helper()
	id := sha256.Sum256([]byte("stream-test-id"))
	sc := scheme{DataShards: uint32(tr.dataShards), ParityShards: uint32(tr.parityShards), Streaming: true}

	var pkts []*protocol.Packet
	err := tr.streamBlocks(bytes.NewReader(data), func(f fragment.Fragment) error {
		for _, piece := range fragmentPieces(f, tr.subChunkSize) {
			p := protocol.NewPacket(protocol.PacketTypeData, piece.Payload, "", "")
			p.ID = id
			p.ChunkNumber = piece.Index
			p.TotalChunks = piece.Total
			p.SubIndex = piece.SubIndex
			p.SubTotal = piece.SubTotal
			stampStreaming(p, piece)
			applyScheme(p, sc)
			pkts = append(pkts, p)
		}
		return nil
	}, id, tr.sealer, 0)
	if err != nil {
		t.Fatalf("streamBlocks: %v", err)
	}
	if reorder != nil {
		reorder(pkts)
	}

	sink := &captureSink{}
	tr.streamSink = func(id [32]byte) io.WriteCloser { return sink }
	sa := tr.newStreamAssembler(pkts[0])
	for _, p := range pkts {
		sa.add(p)
	}
	return sink.buf.Bytes(), sink.closed
}

func newStreamTransfer(t *testing.T, blockSize, subChunkSize int) *Transfer {
	t.Helper()
	sealer, err := encryption.NewAEADSealer(bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &Transfer{
		sealer:          sealer,
		dataShards:      4,
		parityShards:    2,
		streamBlockSize: blockSize,
		subChunkSize:    subChunkSize,
	}
}

func TestStreamMultiBlockRoundTrip(t *testing.T) {
	tr := newStreamTransfer(t, 1024, 512)
	data := bytes.Repeat([]byte("streaming-payload-"), 500) // ~9KB, several blocks
	got, closed := streamRoundTrip(t, tr, data, nil)
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(data))
	}
	if !closed {
		t.Fatal("sink must be closed once the stream completes")
	}
}

func TestStreamOutOfOrderReassembles(t *testing.T) {
	tr := newStreamTransfer(t, 1024, 512)
	data := bytes.Repeat([]byte("out-of-order-blocks-"), 500)
	// Reverse packet order: later blocks arrive before earlier ones, exercising
	// the in-order flush buffering.
	got, closed := streamRoundTrip(t, tr, data, func(p []*protocol.Packet) {
		for i, j := 0, len(p)-1; i < j; i, j = i+1, j-1 {
			p[i], p[j] = p[j], p[i]
		}
	})
	if !bytes.Equal(got, data) {
		t.Fatalf("out-of-order mismatch: got %d bytes, want %d", len(got), len(data))
	}
	if !closed {
		t.Fatal("sink must close after out-of-order completion")
	}
}

func TestStreamSubChunkedShards(t *testing.T) {
	// Tiny sub-chunk size forces each block's shards to split further.
	tr := newStreamTransfer(t, 4096, 64)
	data := bytes.Repeat([]byte("sub-chunked-stream-"), 400)
	got, _ := streamRoundTrip(t, tr, data, nil)
	if !bytes.Equal(got, data) {
		t.Fatalf("sub-chunked stream mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

func TestStreamTinyFinalBlock(t *testing.T) {
	// Block size 1024; length chosen so the final block is 2 bytes (< dataShards),
	// exercising the zero-pad path.
	tr := newStreamTransfer(t, 1024, 512)
	data := bytes.Repeat([]byte("x"), 1024*2+2)
	got, _ := streamRoundTrip(t, tr, data, nil)
	if !bytes.Equal(got, data) {
		t.Fatalf("tiny-final-block mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

func TestStreamExactMultipleMarksFinal(t *testing.T) {
	// Length an exact multiple of block size: the lookahead must still mark the
	// last full block Final so the stream terminates.
	tr := newStreamTransfer(t, 1024, 512)
	data := bytes.Repeat([]byte("y"), 1024*3)
	got, closed := streamRoundTrip(t, tr, data, nil)
	if !bytes.Equal(got, data) || !closed {
		t.Fatalf("exact-multiple stream failed: got %d bytes (closed=%v), want %d", len(got), closed, len(data))
	}
}

func TestStreamEmpty(t *testing.T) {
	tr := newStreamTransfer(t, 1024, 512)
	got, closed := streamRoundTrip(t, tr, nil, nil)
	if len(got) != 0 || !closed {
		t.Fatalf("empty stream: got %d bytes (closed=%v), want 0 and closed", len(got), closed)
	}
}
