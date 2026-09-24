package protocol

import (
	"bytes"
	"fmt"
	"testing"
)

// Benchmarks for the binary wire codec (P1). Every fragment crosses this twice per
// hop — marshal on send, unmarshal on receive — so it is on the hottest path in
// the stack and the first thing to check before blaming the transport.

func benchPacket(payloadSize int) *Packet {
	const id = "abcdef0123456789abcdef0123456789"
	p := NewPacket(PacketTypeData, bytes.Repeat([]byte("x"), payloadSize), "ANY", id)
	p.SourceNode = id
	p.TotalChunks = 6
	p.ChunkNumber = 2
	return p
}

func BenchmarkPacketMarshal(b *testing.B) {
	for _, n := range []int{1 << 10, 16 << 10, 256 << 10} {
		p := benchPacket(n)
		b.Run(fmt.Sprintf("%dKiB", n>>10), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := p.MarshalBinary(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPacketUnmarshal(b *testing.B) {
	for _, n := range []int{1 << 10, 16 << 10, 256 << 10} {
		raw, err := benchPacket(n).MarshalBinary()
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%dKiB", n>>10), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var p Packet
				if err := p.UnmarshalBinary(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
