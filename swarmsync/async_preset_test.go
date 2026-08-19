package swarmsync

import (
	"bytes"
	"testing"
	"time"
)

func TestPreset(t *testing.T) {
	d := Preset(ProfileDirect)
	if d.HopCount != 0 || d.CoverTraffic || d.RelayScoring {
		t.Fatalf("direct preset should be non-anonymous and plain: %+v", d)
	}
	b := Preset(ProfileBalanced)
	if b.HopCount != 1 || b.Redundancy != 2 || !b.RelayScoring {
		t.Fatalf("balanced preset unexpected: %+v", b)
	}
	a := Preset(ProfileAnonymous)
	if a.HopCount < 2 || !a.CoverTraffic || a.PadCellSize == 0 || a.RelayJitter == 0 || !a.RelayScoring {
		t.Fatalf("anonymous preset should enable the full defense stack: %+v", a)
	}
	// An unknown profile falls back to balanced.
	if u := Preset("nonsense"); u.HopCount != 1 || !u.RelayScoring {
		t.Fatalf("unknown profile should fall back to balanced: %+v", u)
	}
}

// TestSendToAsyncConfirmed verifies SendToAsync does not block the caller even
// with ConfirmDelivery on, and reports success through its callback once the
// recipient's acknowledgement returns.
func TestSendToAsyncConfirmed(t *testing.T) {
	key := bytes.Repeat([]byte{0x6d}, 32)
	payload := bytes.Repeat([]byte("async-confirmed-"), 1000)

	recv := make(chan []byte, 8)
	dest := newTestNode(t, Options{NodeID: "dest", Key: key, Relay: true, OnDataReceived: func(b []byte) { recv <- b }})
	r1 := newTestNode(t, Options{NodeID: "r1", Key: key, Relay: true})
	r2 := newTestNode(t, Options{NodeID: "r2", Key: key, Relay: true})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, HopCount: 1, Redundancy: 2, DataShards: 4, ParityShards: 2, ConfirmDelivery: true})

	nodes := []*SyncSwarm{dest, r1, r2, sender}
	wireAndStart(t, nodes...)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(300 * time.Millisecond)

		cbErr := make(chan error, 1)
		start := time.Now()
		sender.SendToAsync(payload, dest.NodeID(), func(err error) { cbErr <- err })
		// The call must return immediately — well under a confirm round-trip —
		// even though ConfirmDelivery is on.
		if blocked := time.Since(start); blocked > 250*time.Millisecond {
			t.Fatalf("SendToAsync blocked the caller for %v", blocked)
		}

		select {
		case got := <-recv:
			if !bytes.Equal(got, payload) {
				t.Fatalf("delivered %d bytes, want %d", len(got), len(payload))
			}
			// The callback should report the confirmed delivery (nil error).
			select {
			case err := <-cbErr:
				if err != nil {
					continue // this attempt's confirm failed; retry
				}
				return // success: non-blocking send + confirmed callback
			case <-time.After(5 * time.Second):
			}
		case <-time.After(1500 * time.Millisecond):
		}
	}
	t.Fatal("timed out waiting for async confirmed delivery")
}
