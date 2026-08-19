package fragment

import (
	"bytes"
	"testing"

	"github.com/APoniatowski/syncswarm/internal/encryption"
)

func fixedKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

func newSealer(t *testing.T, b byte) encryption.Sealer {
	t.Helper()
	s, err := encryption.NewAEADSealer(fixedKey(b))
	if err != nil {
		t.Fatalf("NewAEADSealer: %v", err)
	}
	return s
}

func TestSplitJoinRoundTrip(t *testing.T) {
	const chunk = 4
	cases := map[string][]byte{
		"empty":           {},
		"less than chunk": {1, 2, 3},
		"equal to chunk":  {1, 2, 3, 4},
		"multiple exact":  {1, 2, 3, 4, 5, 6, 7, 8},
		"multiple+remain": {1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			chunks := Split(data, chunk)
			got := Join(chunks)
			if len(data) == 0 {
				if chunks != nil {
					t.Fatalf("expected nil chunks for empty input, got %v", chunks)
				}
				if len(got) != 0 {
					t.Fatalf("expected empty join, got %v", got)
				}
				return
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("round trip mismatch: got %v want %v", got, data)
			}
			// Verify chunk sizing (all but last == chunk size).
			for i, c := range chunks {
				if i < len(chunks)-1 && len(c) != chunk {
					t.Fatalf("chunk %d has size %d, want %d", i, len(c), chunk)
				}
				if len(c) > chunk {
					t.Fatalf("chunk %d oversized: %d", i, len(c))
				}
			}
		})
	}
}

func TestSplitInvalidChunkSize(t *testing.T) {
	if got := Split([]byte{1, 2, 3}, 0); got != nil {
		t.Fatalf("expected nil for chunkSize 0, got %v", got)
	}
	if got := Split([]byte{1, 2, 3}, -5); got != nil {
		t.Fatalf("expected nil for negative chunkSize, got %v", got)
	}
}

func fragmentAndReassemble(t *testing.T, sender, receiver encryption.Sealer, id [32]byte, data []byte, chunkSize int) ([]byte, error) {
	t.Helper()
	f, err := NewFragmenter(sender, chunkSize)
	if err != nil {
		t.Fatalf("NewFragmenter: %v", err)
	}
	frags, err := f.Fragment(id, data)
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	total := uint32(len(frags))
	r := NewReassembler(receiver, total)
	for _, fr := range frags {
		if err := r.Add(fr); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if !r.Complete() {
		t.Fatalf("expected complete")
	}
	return r.Assemble(id)
}

func TestFragmentReassembleRoundTrip(t *testing.T) {
	s := newSealer(t, 0x11)
	id := [32]byte{1, 2, 3}
	data := bytes.Repeat([]byte("SyncSwarm-payload!"), 100)
	got, err := fragmentAndReassemble(t, s, s, id, data, 16)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round trip mismatch")
	}
}

func TestNewFragmenterErrors(t *testing.T) {
	if _, err := NewFragmenter(nil, 16); err == nil {
		t.Fatalf("expected error for nil sealer")
	}
	s := newSealer(t, 0x22)
	if _, err := NewFragmenter(s, 0); err == nil {
		t.Fatalf("expected error for zero chunk size")
	}
}

func TestMissingFragment(t *testing.T) {
	s := newSealer(t, 0x33)
	f, _ := NewFragmenter(s, 8)
	id := [32]byte{9}
	frags, err := f.Fragment(id, bytes.Repeat([]byte{0xAB}, 40))
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	r := NewReassembler(s, uint32(len(frags)))
	// Add all but the last.
	for _, fr := range frags[:len(frags)-1] {
		if err := r.Add(fr); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if r.Complete() {
		t.Fatalf("expected incomplete")
	}
	if _, err := r.Assemble(id); err == nil {
		t.Fatalf("expected error assembling incomplete transfer")
	}
}

func TestWrongKeyFails(t *testing.T) {
	sender := newSealer(t, 0x44)
	receiver := newSealer(t, 0x55) // different key
	id := [32]byte{7}
	data := bytes.Repeat([]byte("data"), 20)
	if _, err := fragmentAndReassemble(t, sender, receiver, id, data, 12); err == nil {
		t.Fatalf("expected error with mismatched keys")
	}
}

func TestTamperedPayloadFails(t *testing.T) {
	s := newSealer(t, 0x66)
	f, _ := NewFragmenter(s, 8)
	id := [32]byte{3, 1, 4}
	frags, err := f.Fragment(id, bytes.Repeat([]byte{0xCD}, 30))
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	frags[0].Payload[len(frags[0].Payload)-1] ^= 0xFF // flip a byte
	r := NewReassembler(s, uint32(len(frags)))
	for _, fr := range frags {
		if err := r.Add(fr); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if _, err := r.Assemble(id); err == nil {
		t.Fatalf("expected error assembling tampered transfer")
	}
}

func TestWrongTransferIDFails(t *testing.T) {
	s := newSealer(t, 0x77)
	f, _ := NewFragmenter(s, 8)
	id := [32]byte{1}
	frags, err := f.Fragment(id, bytes.Repeat([]byte{0xEE}, 20))
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	r := NewReassembler(s, uint32(len(frags)))
	for _, fr := range frags {
		if err := r.Add(fr); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	wrongID := [32]byte{2}
	if _, err := r.Assemble(wrongID); err == nil {
		t.Fatalf("expected error with wrong transfer ID (aad mismatch)")
	}
}

func TestAddValidation(t *testing.T) {
	s := newSealer(t, 0x88)
	r := NewReassembler(s, 3)
	// Index out of range.
	if err := r.Add(Fragment{Index: 3, Total: 3}); err == nil {
		t.Fatalf("expected ErrIndexRange")
	}
	// Total mismatch.
	if err := r.Add(Fragment{Index: 0, Total: 5}); err == nil {
		t.Fatalf("expected ErrTotalMismatch")
	}
	// Valid add, then duplicate ignored.
	if err := r.Add(Fragment{Index: 0, Total: 3, Payload: []byte("x")}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := r.Add(Fragment{Index: 0, Total: 3, Payload: []byte("y")}); err != nil {
		t.Fatalf("duplicate Add should be ignored, got %v", err)
	}
	if len(r.parts) != 1 {
		t.Fatalf("duplicate should not overwrite, parts=%d", len(r.parts))
	}
}
