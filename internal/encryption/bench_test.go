package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"testing"
)

// Benchmarks for the sealing and onion hot paths — the per-fragment costs that
// dominate transfer throughput, and the inputs the ROADMAP's "benchmark before
// weighing a rewrite" decision needs.

func benchSizes() []int { return []int{1 << 10, 16 << 10, 256 << 10} }

func BenchmarkAEADSeal(b *testing.B) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	s, err := NewAEADSealer(key)
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range benchSizes() {
		payload := bytes.Repeat([]byte("x"), n)
		b.Run(fmt.Sprintf("%dKiB", n>>10), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := s.Seal(payload, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAEADOpen(b *testing.B) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	s, _ := NewAEADSealer(key)
	for _, n := range benchSizes() {
		ct, err := s.Seal(bytes.Repeat([]byte("x"), n), nil)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%dKiB", n>>10), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := s.Open(ct, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSealHybrid measures per-recipient sealing (ephemeral X25519 + HKDF +
// AES-GCM) — the cost of the no-shared-key mode, per fragment.
func BenchmarkSealHybrid(b *testing.B) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 16<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := SealHybrid(priv.PublicKey(), payload, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func onionHops(b *testing.B, n int) ([]OnionHop, []*ecdh.PrivateKey) {
	b.Helper()
	hops := make([]OnionHop, 0, n)
	privs := make([]*ecdh.PrivateKey, 0, n)
	for i := 0; i < n; i++ {
		p, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		privs = append(privs, p)
		hops = append(hops, OnionHop{
			NodeID: fmt.Sprintf("node%02d", i),
			Addr:   fmt.Sprintf("10.0.0.%d:64513", i+1),
			PubKey: p.PublicKey(),
		})
	}
	return hops, privs
}

// BenchmarkBuildOnion measures the sender-side cost of wrapping a fragment in one
// layer per hop — the inherent price of anonymity, and how it scales with depth.
func BenchmarkBuildOnion(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 16<<10)
	for _, depth := range []int{1, 2, 3} {
		hops, _ := onionHops(b, depth)
		b.Run(fmt.Sprintf("%dhop", depth), func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := BuildOnion(hops, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkPeelOnion measures a relay's per-packet forwarding cost: peel exactly
// one layer. This is the number that bounds relay throughput.
func BenchmarkPeelOnion(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 16<<10)
	for _, depth := range []int{1, 3} {
		hops, privs := onionHops(b, depth)
		blob, err := BuildOnion(hops, payload)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%dhop", depth), func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := PeelOnion(privs[0], blob); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
