package iface

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"
)

// TestKISS_EncodeDecodeRoundTrip covers framing including escaping of the special
// FEND/FESC bytes inside the payload.
func TestKISS_EncodeDecodeRoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("hello radio"),
		{kissFEND, kissFESC, kissTFEND, kissTFESC}, // all specials
		bytes.Repeat([]byte{kissFEND}, 8),          // many FENDs in payload
		{0x00, kissFESC, 0x01, kissFEND, 0x02},     // mixed
	}
	for i, want := range cases {
		enc := kissEncode(want)
		// Prepend some line noise + a stray delimiter to prove resync.
		stream := append([]byte{0x11, 0x22, kissFEND}, enc...)
		r := bufio.NewReader(bytes.NewReader(stream))
		got, err := readKISSFrame(r)
		if err != nil {
			t.Fatalf("case %d: decode: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: got %v, want %v", i, got, want)
		}
	}
}

// TestKISS_Interface drives the KISS interface over an in-memory pipe in both
// directions: inbound frames surface on Frames(), and Send emits a valid KISS
// frame on the wire.
func TestKISS_Interface(t *testing.T) {
	mine, peer := net.Pipe()
	k := NewKISSInterface("k", mine, KindLoRa, Caps{MTU: 500, Broadcast: true})
	defer k.Close()

	// Inbound: peer transmits a KISS frame; it must arrive on Frames().
	go func() { peer.Write(kissEncode([]byte("from-air"))) }()
	select {
	case f := <-k.Frames():
		if string(f.Data) != "from-air" {
			t.Fatalf("inbound = %q, want from-air", f.Data)
		}
		if f.Addr != "" {
			t.Fatalf("radio frame carried addr %q, want empty (broadcast RF)", f.Addr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no inbound frame")
	}

	// Outbound: Send must write a KISS frame the peer can decode.
	got := make(chan []byte, 1)
	go func() {
		r := bufio.NewReader(peer)
		frame, err := readKISSFrame(r)
		if err != nil {
			t.Errorf("peer decode: %v", err)
			return
		}
		got <- frame
	}()
	if err := k.Send(Broadcast, []byte("to-air")); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		if string(f) != "to-air" {
			t.Fatalf("outbound = %q, want to-air", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send produced no decodable frame")
	}
}

func TestKISS_RejectsOversize(t *testing.T) {
	mine, _ := net.Pipe()
	k := NewKISSInterface("k", mine, KindSerial, Caps{MTU: 16})
	defer k.Close()
	if err := k.Send(Broadcast, make([]byte, 17)); err == nil {
		t.Fatal("oversize frame should be rejected")
	}
}
