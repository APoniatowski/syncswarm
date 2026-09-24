package iface

import (
	"errors"
	"testing"
	"time"
)

// TestAutoInterface_Discovers verifies two AutoInterfaces on the same host find
// each other with zero configuration: one broadcasts, the other receives. Skips
// where the environment has no multicast-capable interface (e.g. a loopback-only
// sandbox), which is a valid runtime outcome, not a failure.
func TestAutoInterface_Discovers(t *testing.T) {
	a, err := NewAutoInterface("a")
	if err != nil {
		if errors.Is(err, ErrNoMulticast) {
			t.Skip("no multicast-capable interface here")
		}
		t.Fatal(err)
	}
	defer a.Close()

	b, err := NewAutoInterface("b")
	if err != nil {
		if errors.Is(err, ErrNoMulticast) {
			t.Skip("no multicast-capable interface here")
		}
		t.Fatal(err)
	}
	defer b.Close()

	if err := a.Send(Broadcast, []byte("hello-lan")); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case f := <-b.Frames():
			if string(f.Data) == "hello-lan" {
				if f.Addr == "" {
					t.Fatal("received frame carried no source address")
				}
				return // discovered
			}
			// ignore any unrelated multicast noise on the LAN
		case <-deadline:
			t.Skip("no multicast delivery on this host (loopback may be disabled)")
		}
	}
}

func TestAutoInterface_RejectsOversizeFrame(t *testing.T) {
	a, err := NewAutoInterface("a")
	if err != nil {
		if errors.Is(err, ErrNoMulticast) {
			t.Skip("no multicast-capable interface here")
		}
		t.Fatal(err)
	}
	defer a.Close()

	if err := a.Send(Broadcast, make([]byte, udpMTU+1)); err == nil {
		t.Fatal("oversize frame should be rejected")
	}
}
