package transfer

import (
	"context"
	"net"
	"testing"
	"time"
)

func testContext() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

// TestAcceptConnections_BoundsConcurrency guards the other half of the
// pre-allocation DoS. Bounding per-operation I/O time is not enough on its own:
// each in-flight connection costs a goroutine and, on its first frame, a buffer
// sized by the length the peer declares. With an unbounded accept loop those
// costs multiply by however many sockets a stranger cares to open, so the node
// must refuse connections past a ceiling rather than queue them.
func TestAcceptConnections_BoundsConcurrency(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tr := &Transfer{
		listener:  ln,
		connSlots: make(chan struct{}, 4), // small ceiling to keep the test quick
	}
	tr.ctx, tr.cancel = testContext()
	defer tr.cancel()

	// Occupy every slot, as connections that have not yet sent a frame would.
	for i := 0; i < cap(tr.connSlots); i++ {
		tr.connSlots <- struct{}{}
	}

	go tr.acceptConnections()

	// A further connection must be closed promptly rather than served or parked.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("connection past the ceiling was served instead of shed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection past the ceiling was parked, not closed: an attacker " +
			"can still pin resources by opening sockets")
	}

	// Freeing a slot must let the next connection through again, so the limit
	// sheds load rather than wedging the listener permanently.
	<-tr.connSlots
	c2, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial after slot freed: %v", err)
	}
	defer c2.Close()
	if err := c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Read(buf); err != nil {
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("connection was shed after a slot was freed: %v", err)
		}
	}
}

// TestEnforceRetainedStreamCap bounds the one piece of receiver state that
// deliberately outlives its connection. Because a retained resumable partial
// survives disconnect and is only reclaimed after an hour, the connection limit
// does not constrain it: a peer can connect, declare a resumable stream, drop, and
// repeat, accumulating state for the whole TTL.
func TestEnforceRetainedStreamCap(t *testing.T) {
	tr := &Transfer{}
	base := time.Now().Add(-time.Hour)

	// More retained partials than the cap, oldest first.
	const over = 40
	for i := 0; i < maxRetainedStreams+over; i++ {
		var id [32]byte
		id[0], id[1] = byte(i), byte(i>>8)
		tr.transfers.Store(id, &transferState{
			ID:     id,
			scheme: scheme{Resumable: true, Streaming: true},
			stream: &streamAssembler{lastActivity: base.Add(time.Duration(i) * time.Second)},
		})
	}

	tr.enforceRetainedStreamCap()

	n := 0
	tr.transfers.Range(func(_, _ any) bool { n++; return true })
	if n != maxRetainedStreams {
		t.Fatalf("retained %d streams, want the cap of %d", n, maxRetainedStreams)
	}

	// The survivors must be the most recently active: evicting the newest instead
	// would let a flood of stale entries push out the resume someone is waiting on.
	var oldest [32]byte
	oldest[0] = 0
	if _, ok := tr.transfers.Load(oldest); ok {
		t.Fatal("least recently active stream survived; eviction order is wrong")
	}
	var newest [32]byte
	last := maxRetainedStreams + over - 1
	newest[0], newest[1] = byte(last), byte(last>>8)
	if _, ok := tr.transfers.Load(newest); !ok {
		t.Fatal("most recently active stream was evicted")
	}
}
