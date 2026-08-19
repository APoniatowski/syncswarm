package discovery

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/link"
)

// TestLink_OverRealUDP establishes an encrypted Link between two Discovery nodes
// over a real UDP interface and exchanges data both ways — proving the session
// layer rides the actual network transport, not just an in-memory pipe.
func TestLink_OverRealUDP(t *testing.T) {
	b, _ := realDiscovery(t, "relay")
	a, _ := realDiscovery(t)
	a.Start()
	defer a.Stop()
	b.Start()
	defer b.Stop()

	if a.Links() == nil || b.Links() == nil {
		t.Fatal("link managers should be enabled when a signing key is set")
	}

	recvB := make(chan []byte, 1)
	var lb *link.Link
	ready := make(chan struct{}, 1)
	b.Links().OnInboundLink(func(l *link.Link) {
		lb = l
		l.OnData(func(d []byte) { recvB <- d })
		select {
		case ready <- struct{}{}:
		default:
		}
	})

	bAddr := fmt.Sprintf("127.0.0.1:%d", b.Port())
	la, err := a.Links().Dial(bAddr, b.signPub, 3*time.Second)
	if err != nil {
		t.Fatalf("dial link over UDP: %v", err)
	}

	// A -> B, encrypted over the wire.
	if err := la.Send([]byte("secret over the wire")); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case got := <-recvB:
		if !bytes.Equal(got, []byte("secret over the wire")) {
			t.Fatalf("B got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("B never received the link data over UDP")
	}

	// B -> A, same session key.
	<-ready
	recvA := make(chan []byte, 1)
	la.OnData(func(d []byte) { recvA <- d })
	if err := lb.Send([]byte("reply over the wire")); err != nil {
		t.Fatalf("reply: %v", err)
	}
	select {
	case got := <-recvA:
		if !bytes.Equal(got, []byte("reply over the wire")) {
			t.Fatalf("A got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("A never received B's reply over UDP")
	}
}
