package fragment

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/APoniatowski/syncswarm/internal/encryption"
)

func rsSealer(t *testing.T) encryption.Sealer {
	t.Helper()
	s, err := encryption.NewAEADSealer(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRSRoundTripAllShards(t *testing.T) {
	sealer := rsSealer(t)
	id := sha256.Sum256([]byte("rs"))
	data := bytes.Repeat([]byte("erasure-coded-payload-"), 500)

	f, err := NewRSFragmenter(sealer, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	frags, origLen, err := f.Fragment(id, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 6 || origLen != len(data) {
		t.Fatalf("frags=%d origLen=%d, want 6 and %d", len(frags), origLen, len(data))
	}

	r := NewRSReassembler(sealer, 4, 2, origLen)
	for _, fr := range frags {
		if err := r.Add(fr); err != nil {
			t.Fatal(err)
		}
	}
	got, err := r.Reconstruct(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("reconstructed %d bytes, want %d", len(got), len(data))
	}
}

// TestRSReconstructsWithLostShards is the core erasure-coding property: with
// dataShards=4, parityShards=2, dropping any 2 shards still reconstructs.
func TestRSReconstructsWithLostShards(t *testing.T) {
	sealer := rsSealer(t)
	id := sha256.Sum256([]byte("rs-loss"))
	data := bytes.Repeat([]byte("survive-the-drop!"), 300)

	f, _ := NewRSFragmenter(sealer, 4, 2)
	frags, origLen, err := f.Fragment(id, data)
	if err != nil {
		t.Fatal(err)
	}

	// Drop two arbitrary shards (indices 1 and 4).
	r := NewRSReassembler(sealer, 4, 2, origLen)
	for _, fr := range frags {
		if fr.Index == 1 || fr.Index == 4 {
			continue
		}
		if err := r.Add(fr); err != nil {
			t.Fatal(err)
		}
	}
	if r.Count() != 4 || !r.Enough() {
		t.Fatalf("count=%d enough=%v, want 4/true", r.Count(), r.Enough())
	}
	got, err := r.Reconstruct(id)
	if err != nil {
		t.Fatalf("reconstruct with 2 lost shards: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("reconstructed data mismatch after dropping 2 shards")
	}
}

func TestRSTooFewShards(t *testing.T) {
	sealer := rsSealer(t)
	id := sha256.Sum256([]byte("rs-few"))
	data := bytes.Repeat([]byte("x"), 100)

	f, _ := NewRSFragmenter(sealer, 4, 2)
	frags, origLen, _ := f.Fragment(id, data)

	// Only 3 shards (< dataShards=4) -> cannot reconstruct.
	r := NewRSReassembler(sealer, 4, 2, origLen)
	for _, fr := range frags[:3] {
		_ = r.Add(fr)
	}
	if r.Enough() {
		t.Fatal("3 of 4 data shards should not be enough")
	}
	if _, err := r.Reconstruct(id); err == nil {
		t.Fatal("expected reconstruct to fail with too few shards")
	}
}

func TestRSCorruptShardTreatedAsMissing(t *testing.T) {
	sealer := rsSealer(t)
	id := sha256.Sum256([]byte("rs-corrupt"))
	data := bytes.Repeat([]byte("integrity"), 200)

	f, _ := NewRSFragmenter(sealer, 4, 2)
	frags, origLen, _ := f.Fragment(id, data)

	r := NewRSReassembler(sealer, 4, 2, origLen)
	for i := range frags {
		if i == 0 {
			// Corrupt one shard's ciphertext; it must be treated as missing.
			frags[i].Payload = append([]byte(nil), frags[i].Payload...)
			frags[i].Payload[len(frags[i].Payload)-1] ^= 0xff
		}
		_ = r.Add(frags[i])
	}
	// 6 received, 1 corrupt -> 5 valid >= 4, reconstruct still succeeds.
	got, err := r.Reconstruct(id)
	if err != nil {
		t.Fatalf("reconstruct with 1 corrupt shard: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("data mismatch with 1 corrupt shard")
	}
}

func TestRSInvalidConfig(t *testing.T) {
	sealer := rsSealer(t)
	if _, err := NewRSFragmenter(sealer, 0, 2); err != ErrShardCount {
		t.Fatalf("dataShards=0: got %v", err)
	}
	if _, err := NewRSFragmenter(nil, 4, 2); err != ErrNilSealer {
		t.Fatalf("nil sealer: got %v", err)
	}
	f, _ := NewRSFragmenter(sealer, 8, 2)
	if _, _, err := f.Fragment(sha256.Sum256([]byte("x")), []byte("tiny")); err != ErrShortData {
		t.Fatalf("short data: got %v", err)
	}
}
