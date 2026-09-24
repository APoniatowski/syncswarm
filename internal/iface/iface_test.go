package iface

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// Compile-time proof that every concrete transport satisfies Interface.
var (
	_ Interface = (*UDPInterface)(nil)
	_ Interface = (*TCPServerInterface)(nil)
	_ Interface = (*TCPClientInterface)(nil)
	_ Interface = (*LoRaInterface)(nil)
	_ Interface = (*SerialInterface)(nil)
)

func recvFrame(t *testing.T, ch <-chan InboundFrame, d time.Duration) InboundFrame {
	t.Helper()
	select {
	case f, ok := <-ch:
		if !ok {
			t.Fatal("frames channel closed while awaiting a frame")
		}
		return f
	case <-time.After(d):
		t.Fatal("timed out waiting for frame")
		return InboundFrame{}
	}
}

func TestUDPUnicastLoopback(t *testing.T) {
	sender, err := NewUDPInterface("a", "127.0.0.1:0", "")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := NewUDPInterface("b", "127.0.0.1:0", "")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	payload := []byte("announce-me")
	if err := sender.Send(receiver.LocalAddr().String(), payload); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := recvFrame(t, receiver.Frames(), 2*time.Second)
	if !bytes.Equal(got.Data, payload) {
		t.Fatalf("got %q, want %q", got.Data, payload)
	}
}

func TestUDPMTUEnforced(t *testing.T) {
	u, err := NewUDPInterface("a", "127.0.0.1:0", "")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if err := u.Send("127.0.0.1:1", make([]byte, udpMTU+1)); err == nil {
		t.Fatal("expected MTU-exceeded error, got nil")
	}
	if !u.Caps().FullDuplex || u.Caps().MTU != udpMTU {
		t.Fatalf("unexpected caps: %+v", u.Caps())
	}
}

func TestTCPBidirectionalLoopback(t *testing.T) {
	server, err := NewTCPServerInterface("srv", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewTCPClientInterface("cli", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// client -> server
	up := []byte("client-hello")
	if err := client.Send(Broadcast, up); err != nil {
		t.Fatalf("client send: %v", err)
	}
	got := recvFrame(t, server.Frames(), 2*time.Second)
	if !bytes.Equal(got.Data, up) {
		t.Fatalf("server got %q, want %q", got.Data, up)
	}

	// server -> client (reply to the addr we just learned)
	down := []byte("server-hello")
	if err := server.Send(got.Addr, down); err != nil {
		t.Fatalf("server send: %v", err)
	}
	back := recvFrame(t, client.Frames(), 2*time.Second)
	if !bytes.Equal(back.Data, down) {
		t.Fatalf("client got %q, want %q", back.Data, down)
	}
}

func TestTCPServerBroadcast(t *testing.T) {
	server, err := NewTCPServerInterface("srv", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	c1, err := NewTCPClientInterface("c1", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := NewTCPClientInterface("c2", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	// Wait for both connections to register server-side before broadcasting.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		server.mu.RLock()
		n := len(server.conns)
		server.mu.RUnlock()
		if n == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	msg := []byte("to-all")
	if err := server.Send(Broadcast, msg); err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	if got := recvFrame(t, c1.Frames(), 2*time.Second); !bytes.Equal(got.Data, msg) {
		t.Fatalf("c1 got %q", got.Data)
	}
	if got := recvFrame(t, c2.Frames(), 2*time.Second); !bytes.Equal(got.Data, msg) {
		t.Fatalf("c2 got %q", got.Data)
	}
}

// TestRadioKindsAndCaps checks the LoRa/serial radio interfaces report the right
// medium properties, exercised over an in-memory pipe (no hardware). The serial
// device opener is covered on Linux only; here we drive the KISS engine directly.
func TestRadioKindsAndCaps(t *testing.T) {
	_, pipe := net.Pipe()
	k := NewKISSInterface("lora0", pipe, KindLoRa, Caps{MTU: 500, Broadcast: true})
	defer k.Close()

	if k.Kind() != KindLoRa {
		t.Fatalf("kind = %v, want %v", k.Kind(), KindLoRa)
	}
	if k.Caps().MTU != 500 {
		t.Fatalf("MTU = %d, want 500", k.Caps().MTU)
	}
	if err := k.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
