package transfer

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// TestDeadlineConn_UnblocksSilentPeer is the regression test for unbounded
// data-plane I/O: dialing was bounded, but an established connection was not. A
// peer that accepts a connection and then never speaks — a half-open NAT mapping,
// a hung process — blocked a read forever, and connPool could hand that same dead
// connection to later sends.
func TestDeadlineConn_UnblocksSilentPeer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A peer that accepts and then says nothing at all, holding the connection open.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c // keep it open, never write
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	// Short timeout so the test is fast; production uses ioTimeout.
	conn := &deadlineConn{Conn: raw, timeout: 300 * time.Millisecond}

	start := time.Now()
	_, err = bufio.NewReader(conn).ReadByte()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("read returned data from a peer that never wrote anything")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("read failed with %v; want a timeout error", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("read took %v — it was not bounded by the deadline", elapsed)
	}
	t.Logf("silent peer unblocked after %v instead of hanging", elapsed.Round(time.Millisecond))

	if c := <-accepted; c != nil {
		c.Close()
	}
}

// TestDeadlineConn_ProgressIsNotCutOff checks the deadline is per-operation, not
// absolute: a slow-but-progressing transfer must not be killed just because it
// runs longer than one timeout in total.
func TestDeadlineConn_ProgressIsNotCutOff(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Trickle: each byte arrives well inside one timeout, but the whole
		// exchange lasts several timeouts.
		for i := 0; i < 6; i++ {
			time.Sleep(120 * time.Millisecond)
			if _, err := c.Write([]byte{byte('a' + i)}); err != nil {
				return
			}
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := &deadlineConn{Conn: raw, timeout: 300 * time.Millisecond}

	br := bufio.NewReader(conn)
	for i := 0; i < 6; i++ {
		b, err := br.ReadByte()
		if err != nil {
			t.Fatalf("byte %d: %v — a progressing transfer was cut off; the deadline "+
				"must be re-armed per operation, not applied to the whole connection", i, err)
		}
		if b != byte('a'+i) {
			t.Fatalf("byte %d = %q, want %q", i, b, byte('a'+i))
		}
	}
}
