package iface

import (
	"net"
	"testing"
	"time"
)

// TestTCPClient_Reconnects verifies a bridge self-heals: after its connection
// drops, the client redials the same address and resumes carrying frames.
func TestTCPClient_Reconnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	cli, err := NewTCPClientInterface("cli", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// First connection, then simulate a drop.
	var c1 net.Conn
	select {
	case c1 = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("client never made its first connection")
	}
	c1.Close()

	// The client must redial (backoff starts at 1s) and get a fresh connection.
	var c2 net.Conn
	select {
	case c2 = <-accepted:
	case <-time.After(6 * time.Second):
		t.Fatal("client did not reconnect after the drop")
	}
	defer c2.Close()

	// A frame over the new connection must surface — proving the bridge resumed.
	if err := writeFrame(c2, []byte("after-reconnect")); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-cli.Frames():
		if string(f.Data) != "after-reconnect" {
			t.Fatalf("got %q, want %q", f.Data, "after-reconnect")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no frame received after reconnect")
	}
}

// TestTCPClient_CloseWhileReconnecting ensures Close returns promptly even if the
// client is mid-reconnect to an address that's gone (no 10s dial hang).
func TestTCPClient_CloseWhileReconnecting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	cli, err := NewTCPClientInterface("cli", addr)
	if err != nil {
		t.Fatal(err)
	}
	// Kill the listener so redials fail; the client enters its backoff/redial loop.
	ln.Close()
	time.Sleep(1500 * time.Millisecond) // let it drop and start reconnecting

	done := make(chan struct{})
	go func() { cli.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung while the client was reconnecting")
	}
}
