// Package fragment splits payloads into fixed-size chunks and, in its sealed
// pipeline, encrypts each chunk independently so that a relay holding a single
// shard learns nothing about the plaintext.
//
// Two layers are provided:
//
//   - Plain chunking helpers (Split/Join) that move raw bytes.
//   - A sealed pipeline (Fragmenter/Reassembler) that seals each chunk with an
//     encryption.Sealer, binding the transfer ID and the fragment's position as
//     associated data so a fragment cannot be replayed at another index.
package fragment

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/APoniatowski/syncswarm/internal/encryption"
)

// Errors returned by the fragment package.
var (
	// ErrNilSealer is returned when a nil Sealer is supplied.
	ErrNilSealer = errors.New("fragment: sealer must not be nil")
	// ErrChunkSize is returned when a non-positive chunk size is supplied.
	ErrChunkSize = errors.New("fragment: chunk size must be positive")
	// ErrIndexRange is returned when a fragment's index is >= its total.
	ErrIndexRange = errors.New("fragment: index out of range")
	// ErrTotalMismatch is returned when a fragment's total disagrees with the
	// reassembler's configured total.
	ErrTotalMismatch = errors.New("fragment: total mismatch")
	// ErrIncomplete is returned when Assemble is called before all fragments
	// are present.
	ErrIncomplete = errors.New("fragment: transfer incomplete")
)

// Fragment is a single positioned piece of a transfer. In the sealed pipeline
// Payload holds the sealed ciphertext; the plain helpers deal in raw bytes.
type Fragment struct {
	TransferID [32]byte
	Index      uint32 // 0-based logical shard/chunk index
	Total      uint32 // number of logical shards/chunks
	Payload    []byte

	// Sub-chunking (transport layer): when a logical fragment's payload is larger
	// than the transport can carry in one packet it is split into SubTotal pieces
	// sharing Index; SubIndex is this piece's 0-based position. SubTotal <= 1
	// means the fragment is carried whole. See transfer.fragmentPieces.
	SubIndex uint32
	SubTotal uint32

	// Streaming (block-wise RS): when Streaming is set, Index/Total are the shard
	// position WITHIN block BlockIndex, BlockLen is that block's pre-encoding
	// length, and Final marks the last block's shards. See transfer streaming.
	Streaming  bool
	BlockIndex uint32
	BlockLen   uint32
	Final      bool
}

// Split divides data into chunkSize-byte chunks; the final chunk may be short.
// It returns nil for empty input or a non-positive chunkSize.
func Split(data []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 || len(data) == 0 {
		return nil
	}
	n := (len(data) + chunkSize - 1) / chunkSize
	chunks := make([][]byte, 0, n)
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// Join concatenates chunks in order. Join(Split(d, n)) equals d.
func Join(chunks [][]byte) []byte {
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// aad binds a fragment's position to its ciphertext. It is deterministic:
// transferID ++ big-endian(index) ++ big-endian(total).
func aad(transferID [32]byte, index, total uint32) []byte {
	b := make([]byte, 0, len(transferID)+8)
	b = append(b, transferID[:]...)
	b = binary.BigEndian.AppendUint32(b, index)
	b = binary.BigEndian.AppendUint32(b, total)
	return b
}

// Fragmenter splits data into chunks and seals each one independently.
type Fragmenter struct {
	sealer    encryption.Sealer
	chunkSize int
}

// NewFragmenter returns a Fragmenter. It errors on a nil sealer or a
// non-positive chunkSize.
func NewFragmenter(sealer encryption.Sealer, chunkSize int) (*Fragmenter, error) {
	if sealer == nil {
		return nil, ErrNilSealer
	}
	if chunkSize <= 0 {
		return nil, ErrChunkSize
	}
	return &Fragmenter{sealer: sealer, chunkSize: chunkSize}, nil
}

// Fragment splits data into chunks and seals each chunk with the transfer ID
// and its position as associated data. The returned Fragments carry the sealed
// ciphertext in Payload and correct Index/Total values.
func (f *Fragmenter) Fragment(transferID [32]byte, data []byte) ([]Fragment, error) {
	chunks := Split(data, f.chunkSize)
	total := uint32(len(chunks))
	frags := make([]Fragment, 0, len(chunks))
	for i, chunk := range chunks {
		index := uint32(i)
		sealed, err := f.sealer.Seal(chunk, aad(transferID, index, total))
		if err != nil {
			return nil, fmt.Errorf("fragment: sealing chunk %d: %w", index, err)
		}
		frags = append(frags, Fragment{
			TransferID: transferID,
			Index:      index,
			Total:      total,
			Payload:    sealed,
		})
	}
	return frags, nil
}

// Reassembler collects sealed fragments and rebuilds the original plaintext.
type Reassembler struct {
	sealer encryption.Sealer
	total  uint32
	parts  map[uint32]Fragment
}

// NewReassembler returns a Reassembler expecting total fragments.
func NewReassembler(sealer encryption.Sealer, total uint32) *Reassembler {
	return &Reassembler{
		sealer: sealer,
		total:  total,
		parts:  make(map[uint32]Fragment, total),
	}
}

// Add stores a fragment by index, ignoring duplicates. It errors if the
// fragment's index is out of range or its total disagrees with the configured
// total.
func (r *Reassembler) Add(fr Fragment) error {
	if fr.Total != r.total {
		return ErrTotalMismatch
	}
	if fr.Index >= r.total {
		return ErrIndexRange
	}
	if _, ok := r.parts[fr.Index]; ok {
		return nil // duplicate, ignore
	}
	r.parts[fr.Index] = fr
	return nil
}

// Complete reports whether every index in [0, total) has been added.
func (r *Reassembler) Complete() bool {
	return uint32(len(r.parts)) == r.total
}

// Assemble opens each fragment with the same position-binding associated data
// and joins the plaintext in index order. It errors if the transfer is
// incomplete or if any fragment fails to open (wrong key, tampering, or a
// positional replay).
func (r *Reassembler) Assemble(transferID [32]byte) ([]byte, error) {
	if !r.Complete() {
		return nil, ErrIncomplete
	}
	chunks := make([][]byte, r.total)
	for i := uint32(0); i < r.total; i++ {
		fr := r.parts[i]
		plain, err := r.sealer.Open(fr.Payload, aad(transferID, i, r.total))
		if err != nil {
			return nil, fmt.Errorf("fragment: opening fragment %d: %w", i, err)
		}
		chunks[i] = plain
	}
	return Join(chunks), nil
}
