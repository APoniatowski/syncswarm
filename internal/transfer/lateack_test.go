package transfer

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/discovery"
)

// TestSentinelErrors_AreDistinguishable pins the contract an application needs:
// telling "nothing left this device" apart from "it went out and was not
// acknowledged". They call for opposite advice — re-send versus do not re-send,
// because a store-and-forward relay may still be holding the fragments — and the
// only way to tell them apart used to be matching on message text, which any
// rewording would silently break.
func TestSentinelErrors_AreDistinguishable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		sentinel error
		sent     bool // did anything leave the device?
	}{
		{"unreachable", ErrDestinationUnreachable, ErrDestinationUnreachable, false},
		{"no anonymous route", ErrNoAnonymousRoute, ErrNoAnonymousRoute, false},
		{"not confirmed", ErrNotConfirmed, ErrNotConfirmed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Wrapped the way the send path wraps them.
			wrapped := errors.Join(errors.New("context from the send path"), tc.err)
			if !errors.Is(wrapped, tc.sentinel) {
				t.Fatalf("errors.Is could not recover %v from a wrapped error", tc.sentinel)
			}
			// And they must not alias each other, or the branch is meaningless.
			for _, other := range []error{ErrDestinationUnreachable, ErrNoAnonymousRoute, ErrNotConfirmed} {
				if other != tc.sentinel && errors.Is(wrapped, other) {
					t.Fatalf("%v also matches %v; send outcomes must be distinguishable", tc.err, other)
				}
			}
		})
	}
}

// TestLateAck_SurfacedAfterGiveUp is the regression test for the messenger's
// report: a recipient who was offline is redelivered by a store-and-forward relay
// when they return, reassembles, and acks — but by then SendTo has long returned
// an error and the registration had been deleted, so the ack was discarded. The
// message really arrived and the sender's copy said it had not, with no way to
// correct it above the transport.
func TestLateAck_SurfacedAfterGiveUp(t *testing.T) {
	tr := &Transfer{pendingAcks: make(map[[32]byte]*pendingAck)}

	var (
		mu       sync.Mutex
		gotID    [32]byte
		gotDest  string
		gotCalls int
	)
	tr.SetOnDelivered(func(id [32]byte, dest string) {
		mu.Lock()
		defer mu.Unlock()
		gotID, gotDest, gotCalls = id, dest, gotCalls+1
	})

	id := [32]byte{7}
	destKey := []byte("destination-signing-key")
	tr.registerAck(id, destKey, nil)

	// The sender exhausts its attempts and reports ErrNotConfirmed.
	tr.retainForLateAck(id, "peer-1")

	// Later, the ack arrives — authenticated exactly as it would be in flight.
	tr.signalAckFrom(id, destKey)

	mu.Lock()
	defer mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("late ack produced %d callbacks, want 1: the transfer succeeded but "+
			"the sender has no way to learn it", gotCalls)
	}
	if gotID != id || gotDest != "peer-1" {
		t.Fatalf("callback reported (%x, %q), want (%x, %q)", gotID[:4], gotDest, id[:4], "peer-1")
	}
}

// TestLateAck_StillAuthenticated: retaining the registration must not weaken the
// check that stops a transfer-ID-knowing attacker forging a delivery confirmation.
// A forged "delivered" is worse than a missing one — it tells the user a message
// landed when it did not.
func TestLateAck_StillAuthenticated(t *testing.T) {
	tr := &Transfer{pendingAcks: make(map[[32]byte]*pendingAck)}
	var calls int
	tr.SetOnDelivered(func([32]byte, string) { calls++ })

	id := [32]byte{9}
	tr.registerAck(id, []byte("the-real-destination-key"), nil)
	tr.retainForLateAck(id, "peer-2")

	tr.signalAckFrom(id, []byte("an-attackers-key"))
	if calls != 0 {
		t.Fatal("a late ack signed by the wrong key was accepted as delivery confirmation")
	}

	tr.signalAckFrom(id, []byte("the-real-destination-key"))
	if calls != 1 {
		t.Fatalf("the genuine late ack was not accepted (calls=%d)", calls)
	}
}

// TestLateAck_Bounded checks the retained set cannot grow without limit. Retention
// is triggered by a peer *declining* to ack, so it is attacker-influenced.
func TestLateAck_Bounded(t *testing.T) {
	tr := &Transfer{pendingAcks: make(map[[32]byte]*pendingAck)}

	for i := 0; i < maxLateAcks+500; i++ {
		var id [32]byte
		id[0], id[1] = byte(i), byte(i>>8)
		tr.registerAck(id, []byte("k"), nil)
		tr.retainForLateAck(id, "peer")
	}
	tr.ackMu.Lock()
	n := len(tr.pendingAcks)
	tr.ackMu.Unlock()
	if n > maxLateAcks {
		t.Fatalf("retained %d late acks, above the cap of %d", n, maxLateAcks)
	}

	// An expired entry must be reclaimed rather than waiting for pressure.
	tr = &Transfer{pendingAcks: make(map[[32]byte]*pendingAck)}
	old := [32]byte{1}
	tr.registerAck(old, []byte("k"), nil)
	tr.retainForLateAck(old, "peer")
	tr.ackMu.Lock()
	tr.pendingAcks[old].expires = time.Now().Add(-time.Minute)
	tr.ackMu.Unlock()

	fresh := [32]byte{2}
	tr.registerAck(fresh, []byte("k"), nil)
	tr.retainForLateAck(fresh, "peer") // sweeps on insert

	tr.ackMu.Lock()
	_, stillThere := tr.pendingAcks[old]
	tr.ackMu.Unlock()
	if stillThere {
		t.Fatal("an expired late-ack registration was not reclaimed")
	}
}

// TestLateAck_DoesNotStealAnInFlightAck: a send still waiting must be resolved by
// closing its channel, not by firing the late callback — otherwise SendTo would
// block to its full timeout while the app was told, out of band, that it worked.
func TestLateAck_DoesNotStealAnInFlightAck(t *testing.T) {
	tr := &Transfer{pendingAcks: make(map[[32]byte]*pendingAck)}
	var lateCalls int
	tr.SetOnDelivered(func([32]byte, string) { lateCalls++ })

	id := [32]byte{3}
	destKey := []byte("dest-key")
	ch := tr.registerAck(id, destKey, nil)

	tr.signalAckFrom(id, destKey) // arrives while the sender is still waiting

	select {
	case <-ch:
	default:
		t.Fatal("an in-flight ack did not release the waiting sender")
	}
	if lateCalls != 0 {
		t.Fatalf("an in-flight ack fired the late-delivery callback (%d times)", lateCalls)
	}
}

// TestAck_IsRedundant covers the cost asymmetry around delivery acknowledgements.
//
// A lost ack is not a small failure. The sender waits ackTimeout and then re-sends
// *every fragment of the whole transfer*, up to maxAckAttempts — so losing one
// ~60-byte packet can cost a 256 KiB retransmission three times over, and then be
// reported as unconfirmed even though the data arrived. The ack was previously
// emitted exactly once over exactly one path, with no fallback.
//
// Duplication is the right primitive at this size. Erasure coding would add
// nothing: RS lets any k of n pieces rebuild a large payload, but an ack fits in a
// single packet, so the only failure mode is "lost" and the answer is "send it
// again".
func TestAck_IsRedundant(t *testing.T) {
	if ackRedundancy < 2 {
		t.Fatalf("ackRedundancy is %d: a single ack means one dropped packet costs a "+
			"full retransmission of the entire transfer", ackRedundancy)
	}
	if ackSpread <= 0 {
		t.Fatal("copies are sent back to back; one burst of loss can take all of them")
	}
	// The copies must all land well inside the sender's patience, or the redundancy
	// is decorative — the sender would have already given up and retransmitted.
	if window := time.Duration(ackRedundancy-1) * ackSpread; window >= ackTimeout {
		t.Fatalf("ack copies span %v but the sender resends after %v; the later "+
			"copies arrive too late to prevent the retransmission they exist to avoid",
			window, ackTimeout)
	}
}

// TestAckWithRedundancy_UsesEveryReturnPath: a transfer that arrived with a reply
// block and is also routable has two independent ways home. Selecting only the
// first match left a single point of failure for the one packet whose loss is the
// most expensive.
func TestAckWithRedundancy_UsesEveryReturnPath(t *testing.T) {
	tr := &Transfer{}

	both := &transferState{ID: [32]byte{1}, sourceNode: "peer", routed: true,
		replyBlock: []byte("reply-block")}
	if n := len(tr.ackSenders(both)); n != 1 {
		t.Fatalf("with a reply block and a routed source but no discovery, got %d "+
			"senders, want 1 (the reply block)", n)
	}

	rbOnly := &transferState{ID: [32]byte{2}, replyBlock: []byte("reply-block")}
	if n := len(tr.ackSenders(rbOnly)); n != 1 {
		t.Fatalf("reply block alone: got %d senders, want 1", n)
	}

	directOnly := &transferState{ID: [32]byte{3}, sourceNode: "peer"}
	if n := len(tr.ackSenders(directOnly)); n != 1 {
		t.Fatalf("direct source alone: got %d senders, want 1", n)
	}

	// A transfer with no way home must select nothing rather than panic.
	if n := len(tr.ackSenders(&transferState{ID: [32]byte{4}})); n != 0 {
		t.Fatalf("no return path: got %d senders, want 0", n)
	}

	// And with both a reply block and a usable routed path, both are used — the
	// point of the change.
	tr2 := &Transfer{discovery: &discovery.Discovery{}}
	if n := len(tr2.ackSenders(both)); n != 2 {
		t.Fatalf("with two independent return paths available, got %d senders, want 2", n)
	}
}
