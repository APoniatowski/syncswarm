package fragment

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/APoniatowski/syncswarm/internal/encryption"
)

// Benchmarks for erasure coding — the other half of the per-transfer CPU cost
// (alongside sealing), and the part that scales with shard count.

func benchSealer(b *testing.B) encryption.Sealer {
	b.Helper()
	s, err := encryption.NewAEADSealer(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		b.Fatal(err)
	}
	return s
}

// BenchmarkRSFragment measures split + Reed-Solomon encode + per-shard sealing:
// the full sender-side preparation of a payload.
func BenchmarkRSFragment(b *testing.B) {
	s := benchSealer(b)
	var id [32]byte
	for _, n := range []int{64 << 10, 1 << 20} {
		payload := bytes.Repeat([]byte("x"), n)
		for _, sh := range [][2]int{{4, 2}, {10, 4}} {
			f, err := NewRSFragmenter(s, sh[0], sh[1])
			if err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("%dKiB/%dd%dp", n>>10, sh[0], sh[1]), func(b *testing.B) {
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, _, err := f.Fragment(id, payload); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkRSReconstruct measures the receiver side reconstructing from exactly
// dataShards fragments — i.e. the worst realistic case, where every parity shard
// is needed because data shards were lost.
func BenchmarkRSReconstruct(b *testing.B) {
	s := benchSealer(b)
	var id [32]byte
	for _, n := range []int{64 << 10, 1 << 20} {
		payload := bytes.Repeat([]byte("x"), n)
		for _, sh := range [][2]int{{4, 2}, {10, 4}} {
			data, parity := sh[0], sh[1]
			f, err := NewRSFragmenter(s, data, parity)
			if err != nil {
				b.Fatal(err)
			}
			frags, origLen, err := f.Fragment(id, payload)
			if err != nil {
				b.Fatal(err)
			}
			// Keep only the last `data` fragments, forcing real RS reconstruction
			// rather than a straight concatenation of the data shards.
			kept := frags[len(frags)-data:]
			b.Run(fmt.Sprintf("%dKiB/%dd%dp", n>>10, data, parity), func(b *testing.B) {
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					r := NewRSReassembler(s, data, parity, origLen)
					for _, fr := range kept {
						if err := r.Add(fr); err != nil {
							b.Fatal(err)
						}
					}
					if _, err := r.Reconstruct(id); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
