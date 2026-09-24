package transfer

import (
	"testing"

	"github.com/APoniatowski/syncswarm/internal/fragment"
	"github.com/APoniatowski/syncswarm/internal/protocol"
)

func TestRoutedSubChunkFor(t *testing.T) {
	const big = 4 << 20
	// Unknown MTU -> the configured sub-chunk size.
	if got := routedSubChunkFor(0, big, 0); got != big {
		t.Fatalf("mtu 0: got %d, want %d", got, big)
	}
	// A datagram MTU shrinks the sub-chunk below the configured size.
	if got := routedSubChunkFor(1400, big, 0); got <= 0 || got >= big {
		t.Fatalf("mtu 1400: got %d, not shrunk into (0, %d)", got, big)
	}
	// A tiny MTU floors rather than sizing to zero.
	if got := routedSubChunkFor(300, big, 0); got != minRoutedSubChunk {
		t.Fatalf("tiny mtu: got %d, want floor %d", got, minRoutedSubChunk)
	}
	// A padding cell eats into the budget.
	a := routedSubChunkFor(4000, big, 0)
	b := routedSubChunkFor(4000, big, 512)
	if b >= a {
		t.Fatalf("padding should reduce the budget: pad0=%d pad512=%d", a, b)
	}
}

// TestRoutedFrameFitsMTU proves the sizing keeps a routed frame within the MTU: a
// fragment sized by routedSubChunkFor, wrapped as an inner data packet and then a
// routed packet, marshals to at most the MTU.
func TestRoutedFrameFitsMTU(t *testing.T) {
	const id = "abcdef0123456789abcdef0123456789"
	tr := &Transfer{subChunkSize: 4 << 20, padCell: 0}
	for _, mtu := range []int{1400, 9000} {
		sub := routedSubChunkFor(mtu, tr.subChunkSize, tr.padCell)
		frag := fragment.Fragment{Payload: make([]byte, sub), Index: 0, Total: 1}
		inner, err := tr.buildInnerFragment([32]byte{}, id, id, frag, scheme{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		pkt := protocol.NewPacket(protocol.PacketTypeRouted, protocol.EncodeRouted(16, inner), "", id)
		pkt.SourceNode = id
		b, err := pkt.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > mtu {
			t.Fatalf("mtu %d: routed frame is %d bytes, exceeds MTU", mtu, len(b))
		}
	}
}
