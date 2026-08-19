package fragment

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"

	"github.com/APoniatowski/syncswarm/internal/encryption"
)

// Reed-Solomon errors.
var (
	// ErrShardCount is returned for an invalid data/parity shard configuration.
	ErrShardCount = errors.New("fragment: dataShards and parityShards must be > 0")
	// ErrShortData is returned when the payload is too small to split across the
	// requested number of data shards (needs at least dataShards bytes).
	ErrShortData = errors.New("fragment: data too short for the shard count")
	// ErrTooFewShards is returned when fewer than dataShards valid shards are
	// available to reconstruct the payload.
	ErrTooFewShards = errors.New("fragment: too few shards to reconstruct")
)

// RSFragmenter splits a payload into dataShards data shards plus parityShards
// parity shards (Reed-Solomon), then seals each shard independently. The
// original payload can be reconstructed from ANY dataShards of the total, so up
// to parityShards may be lost or dropped in transit.
type RSFragmenter struct {
	sealer       encryption.Sealer
	dataShards   int
	parityShards int
}

// NewRSFragmenter returns an RSFragmenter. It errors on a nil sealer or a
// non-positive shard count.
func NewRSFragmenter(sealer encryption.Sealer, dataShards, parityShards int) (*RSFragmenter, error) {
	if sealer == nil {
		return nil, ErrNilSealer
	}
	if dataShards <= 0 || parityShards <= 0 {
		return nil, ErrShardCount
	}
	return &RSFragmenter{sealer: sealer, dataShards: dataShards, parityShards: parityShards}, nil
}

// Fragment erasure-codes data into dataShards+parityShards equal-size shards and
// seals each with the transfer ID and its position as associated data. It
// returns the sealed fragments and the original (pre-encoding) length, which the
// reassembler needs to trim padding.
func (f *RSFragmenter) Fragment(transferID [32]byte, data []byte) ([]Fragment, int, error) {
	if len(data) < f.dataShards {
		return nil, 0, ErrShortData
	}
	enc, err := reedsolomon.New(f.dataShards, f.parityShards)
	if err != nil {
		return nil, 0, fmt.Errorf("fragment: new rs encoder: %w", err)
	}
	shards, err := enc.Split(data)
	if err != nil {
		return nil, 0, fmt.Errorf("fragment: rs split: %w", err)
	}
	if err := enc.Encode(shards); err != nil {
		return nil, 0, fmt.Errorf("fragment: rs encode: %w", err)
	}

	total := uint32(len(shards))
	frags := make([]Fragment, 0, len(shards))
	for i, shard := range shards {
		index := uint32(i)
		sealed, err := f.sealer.Seal(shard, aad(transferID, index, total))
		if err != nil {
			return nil, 0, fmt.Errorf("fragment: sealing shard %d: %w", index, err)
		}
		frags = append(frags, Fragment{
			TransferID: transferID,
			Index:      index,
			Total:      total,
			Payload:    sealed,
		})
	}
	return frags, len(data), nil
}

// RSReassembler collects sealed Reed-Solomon shards and rebuilds the original
// payload once at least dataShards of them have arrived.
type RSReassembler struct {
	sealer       encryption.Sealer
	dataShards   int
	parityShards int
	originalLen  int
	total        uint32
	parts        map[uint32][]byte // index -> sealed shard payload
}

// NewRSReassembler returns an RSReassembler for a transfer encoded with the given
// shard configuration and original length.
func NewRSReassembler(sealer encryption.Sealer, dataShards, parityShards, originalLen int) *RSReassembler {
	return &RSReassembler{
		sealer:       sealer,
		dataShards:   dataShards,
		parityShards: parityShards,
		originalLen:  originalLen,
		total:        uint32(dataShards + parityShards),
		parts:        make(map[uint32][]byte, dataShards+parityShards),
	}
}

// Add stores a shard by index, ignoring duplicates. It errors if the shard's
// index or total is inconsistent with the configured shard counts.
func (r *RSReassembler) Add(fr Fragment) error {
	if fr.Total != r.total {
		return ErrTotalMismatch
	}
	if fr.Index >= r.total {
		return ErrIndexRange
	}
	if _, ok := r.parts[fr.Index]; ok {
		return nil
	}
	r.parts[fr.Index] = fr.Payload
	return nil
}

// Count returns the number of distinct shards received so far.
func (r *RSReassembler) Count() int { return len(r.parts) }

// Enough reports whether enough shards have arrived to attempt reconstruction
// (at least dataShards). Reconstruction may still fail if received shards are
// corrupt, in which case more shards are needed.
func (r *RSReassembler) Enough() bool { return len(r.parts) >= r.dataShards }

// Reconstruct opens the received shards (dropping any that fail to open) and
// rebuilds the original payload via Reed-Solomon reconstruction. It errors if
// fewer than dataShards valid shards are available.
func (r *RSReassembler) Reconstruct(transferID [32]byte) ([]byte, error) {
	enc, err := reedsolomon.New(r.dataShards, r.parityShards)
	if err != nil {
		return nil, fmt.Errorf("fragment: new rs encoder: %w", err)
	}

	shards := make([][]byte, r.total)
	valid := 0
	for i := uint32(0); i < r.total; i++ {
		sealed, ok := r.parts[i]
		if !ok {
			continue
		}
		plain, err := r.sealer.Open(sealed, aad(transferID, i, r.total))
		if err != nil {
			continue // treat an unopenable shard as missing so RS can route around it
		}
		shards[i] = plain
		valid++
	}
	if valid < r.dataShards {
		return nil, ErrTooFewShards
	}

	if err := enc.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("fragment: rs reconstruct: %w", err)
	}

	var buf bytes.Buffer
	if err := enc.Join(&buf, shards, r.originalLen); err != nil {
		return nil, fmt.Errorf("fragment: rs join: %w", err)
	}
	return buf.Bytes(), nil
}
