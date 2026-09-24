package link

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

func TestMaxChunkForMTU(t *testing.T) {
	// Unknown/large MTU -> the default (large) chunk.
	if got := maxChunkForMTU(0); got != maxMessageChunk {
		t.Fatalf("mtu 0: got %d, want default %d", got, maxMessageChunk)
	}
	if got := maxChunkForMTU(10 << 20); got != maxMessageChunk {
		t.Fatalf("huge mtu: got %d, want clamp %d", got, maxMessageChunk)
	}
	// Tiny MTU floors, never zero.
	if got := maxChunkForMTU(10); got != minMessageChunk {
		t.Fatalf("tiny mtu: got %d, want floor %d", got, minMessageChunk)
	}
	// Datagram MTUs shrink the chunk below the default.
	for _, mtu := range []int{500, 1400} {
		if got := maxChunkForMTU(mtu); got <= 0 || got >= maxMessageChunk {
			t.Fatalf("mtu %d: chunk %d not shrunk into (0, %d)", mtu, got, maxMessageChunk)
		}
	}
	// Monotonic: a larger MTU never yields a smaller chunk.
	prev := 0
	for _, mtu := range []int{100, 500, 1400, 9000, 65507} {
		got := maxChunkForMTU(mtu)
		if got < prev {
			t.Fatalf("non-monotonic: mtu %d -> %d < previous %d", mtu, got, prev)
		}
		prev = got
	}
}

// TestSendMessage_FrameFitsMTU asserts that at a datagram MTU the on-wire link
// frames SendMessage emits actually fit that MTU — the point of P5 sizing — while
// the payload still reassembles end-to-end.
func TestSendMessage_FrameFitsMTU(t *testing.T) {
	const mtu = 1400
	a, b, bPub := pair(t)
	a.SetMTUFunc(func(string) int { return mtu })

	recv := make(chan []byte, 1)
	b.OnInboundLink(func(l *Link) {
		r := NewReassembler(func(data []byte) { recv <- data })
		l.OnData(r.Feed)
	})

	la, err := a.Dial("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Intercept a's transport: record LinkData frame sizes, then forward as before
	// so the link keeps working.
	var mu sync.Mutex
	var dataFrameSizes []int
	prevSend := a.send
	a.send = func(addr string, frame []byte) error {
		var pkt protocol.Packet
		if err := pkt.UnmarshalBinary(frame); err == nil && pkt.Type == protocol.PacketTypeLinkData {
			mu.Lock()
			dataFrameSizes = append(dataFrameSizes, len(frame))
			mu.Unlock()
		}
		return prevSend(addr, frame)
	}

	payload := bytes.Repeat([]byte("x"), 8*1024) // spans several MTU-sized chunks
	if err := SendMessage(la, payload); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-recv:
		if !bytes.Equal(got, payload) {
			t.Fatalf("reassembled %d bytes, want %d", len(got), len(payload))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("payload never reassembled")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dataFrameSizes) < 2 {
		t.Fatalf("expected multiple chunks at mtu %d, got %d", mtu, len(dataFrameSizes))
	}
	for i, sz := range dataFrameSizes {
		if sz > mtu {
			t.Fatalf("data frame %d is %d bytes, exceeds mtu %d", i, sz, mtu)
		}
	}
}
