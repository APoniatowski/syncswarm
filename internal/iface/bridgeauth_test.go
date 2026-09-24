package iface

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// waitFrame reads one frame from an interface or fails.
func waitFrame(t *testing.T, ch <-chan InboundFrame, why string) []byte {
	t.Helper()
	select {
	case f := <-ch:
		return f.Data
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", why)
		return nil
	}
}

// TestBridgeAuth_CorrectPSKAttaches is the baseline: with a matching key on both
// ends the bridge behaves exactly as an open one.
func TestBridgeAuth_CorrectPSKAttaches(t *testing.T) {
	psk := []byte("correct horse battery staple")
	srv, err := NewTCPServerInterfaceAuth("srv", "127.0.0.1:0", psk)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cli, err := NewTCPClientInterfaceAuth("cli", srv.Addr().String(), psk)
	if err != nil {
		t.Fatalf("authenticated client should attach: %v", err)
	}
	defer cli.Close()

	if err := cli.Send("", []byte("hello")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := string(waitFrame(t, srv.Frames(), "client frame")); got != "hello" {
		t.Fatalf("server got %q, want %q", got, "hello")
	}

	// And the reverse direction, which only works if the server registered the
	// connection after the handshake.
	if err := srv.Send(Broadcast, []byte("world")); err != nil {
		t.Fatalf("server send: %v", err)
	}
	if got := string(waitFrame(t, cli.Frames(), "server frame")); got != "world" {
		t.Fatalf("client got %q, want %q", got, "world")
	}
}

// TestBridgeAuth_WrongPSKRejected is the finding-3 guard: a bridge with a key must
// refuse a peer that does not hold it, rather than accepting every connection.
func TestBridgeAuth_WrongPSKRejected(t *testing.T) {
	srv, err := NewTCPServerInterfaceAuth("srv", "127.0.0.1:0", []byte("the-real-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if cli, err := NewTCPClientInterfaceAuth("cli", srv.Addr().String(), []byte("guessed-key")); err == nil {
		cli.Close()
		t.Fatal("a peer with the wrong PSK attached to the bridge")
	}
	if cli, err := NewTCPClientInterface("cli", srv.Addr().String()); err == nil {
		// An unauthenticated dialer may complete a TCP connect, but must never get
		// its frames read: prove the server does not deliver anything it sends.
		_ = cli.Send("", []byte("unauthenticated"))
		select {
		case f := <-srv.Frames():
			cli.Close()
			t.Fatalf("server accepted a frame from an unauthenticated peer: %q", f.Data)
		case <-time.After(1500 * time.Millisecond):
		}
		cli.Close()
	}
}

// TestBridgeAuth_NoPSKStaysOpen pins the default. A public seed must keep working
// for peers that carry no key at all, so the handshake is skipped when unset.
func TestBridgeAuth_NoPSKStaysOpen(t *testing.T) {
	srv, err := NewTCPServerInterfaceAuth("srv", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cli, err := NewTCPClientInterface("cli", srv.Addr().String())
	if err != nil {
		t.Fatalf("open bridge refused a plain client: %v", err)
	}
	defer cli.Close()

	if err := cli.Send("", []byte("open")); err != nil {
		t.Fatal(err)
	}
	if got := string(waitFrame(t, srv.Frames(), "frame on open bridge")); got != "open" {
		t.Fatalf("got %q, want %q", got, "open")
	}
}

// TestBridgeAuth_ProofIsNotReflectable covers the specific mistake a symmetric
// challenge-response invites: if both directions proved themselves the same way,
// an attacker holding no key could echo the server's own challenge back and then
// replay the server's proof as its own. The two directions therefore use distinct
// labels, and each proof binds both nonces.
func TestBridgeAuth_ProofIsNotReflectable(t *testing.T) {
	psk := []byte("k")
	sn, cn := []byte("server-nonce-value-padding-32byt"), []byte("client-nonce-value-padding-32byt")

	if string(bridgeProof(psk, bridgeLabelClient, sn, cn)) == string(bridgeProof(psk, bridgeLabelServer, sn, cn)) {
		t.Fatal("client and server proofs are identical: a reflected proof would authenticate")
	}
	// Swapping the nonces must change the proof, so a transcript cannot be reused
	// with the roles exchanged.
	if string(bridgeProof(psk, bridgeLabelClient, sn, cn)) == string(bridgeProof(psk, bridgeLabelClient, cn, sn)) {
		t.Fatal("proof does not bind nonce order")
	}
}

// TestBridgeAuth_SilentPeerIsDropped pins two properties at once.
//
// A peer cannot hold a slot open by connecting and never speaking — the handshake
// carries its own deadline. And, importantly, it receives *nothing* while it stays
// silent: the dialer speaks first, so a client that does not know the bridge is
// protected gets no frame at all. That keeps the "connected but received no
// traffic" liveness warning working. An earlier draft had the server open with its
// challenge, which a PSK-less client read as ordinary traffic — marking the bridge
// live and making the misconfiguration completely silent, verified in the field as
// a bridge that looped forever without a single log line.
func TestBridgeAuth_SilentPeerIsDropped(t *testing.T) {
	srv, err := NewTCPServerInterfaceAuth("srv", "127.0.0.1:0", []byte("a-long-enough-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Nothing must arrive unprompted.
	if err := conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	if frame, err := readFrame(r); err == nil {
		t.Fatalf("server sent %d bytes to a peer that had not authenticated; a "+
			"PSK-less client would read this as traffic and never learn it is being "+
			"rejected", len(frame))
	}

	srv.mu.RLock()
	n := len(srv.conns)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("server registered %d unauthenticated connection(s)", n)
	}
}
