package discovery

import "testing"

// TestReachability_SoloResponderCanConclude covers the case a two-relay network
// actually hits: a node with exactly one peer.
//
// Requiring two responders before declaring "unreachable" made AutoNAT inert
// there — every round was inconclusive, so a relay whose data port nothing could
// dial kept advertising "relay" indefinitely and poisoned other nodes' path
// selection. Observed live: a relay listening on all three ports, blocked at the
// cloud firewall, still advertising itself after seven minutes with no verdict.
//
// One responder must therefore be able to conclude, but only on sustained
// evidence, so a single transient failure cannot demote a healthy relay.
func TestReachability_SoloResponderCanConclude(t *testing.T) {
	d := newTestDiscovery("self")
	d.reachPending = map[uint64]chan bool{}

	var got []bool
	d.reachEnabled = true
	d.onReachability = func(r bool) { got = append(got, r) }

	// One responder saying "unreachable" must not be believed immediately.
	for i := 1; i < reachSoloRounds; i++ {
		d.concludeRound(1, false)
		if len(got) != 0 {
			t.Fatalf("demoted after %d solo failure(s); a single flaky peer must not "+
				"demote a healthy relay", i)
		}
	}

	// But sustained agreement must conclude, or the relay never demotes at all.
	d.concludeRound(1, false)
	if len(got) != 1 || got[0] {
		t.Fatalf("after %d consecutive solo failures the node still did not conclude "+
			"it is unreachable (calls: %v)", reachSoloRounds, got)
	}

	// A success resets the streak and flips the verdict back.
	d.concludeRound(1, true)
	if len(got) != 2 || !got[1] {
		t.Fatalf("a successful dial-back did not restore reachability (calls: %v)", got)
	}
	if d.soloFailures != 0 {
		t.Fatalf("success left soloFailures at %d, want 0", d.soloFailures)
	}

	// Nobody answering says nothing either way.
	d.concludeRound(0, false)
	if len(got) != 2 {
		t.Fatalf("a round with no responders changed the verdict (calls: %v)", got)
	}
}
