package link

import (
	"bytes"
	"testing"
	"time"
)

func TestMessage_SingleAndMultiChunk(t *testing.T) {
	a, b, bPub := pair(t)

	recv := make(chan []byte, 4)
	b.OnInboundLink(func(l *Link) {
		r := NewReassembler(func(data []byte) { recv <- data })
		l.OnData(r.Feed)
	})

	la, err := a.Dial("B", bPub, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// A message that fits in one frame.
	small := []byte("a short message")
	// A message spanning several frames (> maxMessageChunk).
	big := bytes.Repeat([]byte("0123456789abcdef"), maxMessageChunk/16+1000)

	for _, want := range [][]byte{small, big} {
		if err := SendMessage(la, want); err != nil {
			t.Fatalf("send: %v", err)
		}
		select {
		case got := <-recv:
			if !bytes.Equal(got, want) {
				t.Fatalf("reassembled %d bytes, want %d", len(got), len(want))
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("message of %d bytes never reassembled", len(want))
		}
	}
}
