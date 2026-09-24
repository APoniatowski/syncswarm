package transfer

import "testing"

// TestUsePerHop_GatedByAnonymity is the load-bearing invariant for Phase 3:
// per-hop transport routing (which exposes the destination to relays and uses a
// shareable path table) must NEVER be used when anonymity is required, so
// ProfileAnonymous always keeps onion source-routing.
func TestUsePerHop_GatedByAnonymity(t *testing.T) {
	cases := []struct {
		name                           string
		perHop, strict, adaptive, want bool
	}{
		{"enabled, non-anonymous", true, false, false, true},
		{"strict anonymity blocks it", true, true, false, false},
		{"adaptive onion blocks it", true, false, true, false},
		{"disabled", false, false, false, false},
	}
	for _, c := range cases {
		tr := &Transfer{perHopRouting: c.perHop, strictAnon: c.strict, adaptiveOnion: c.adaptive}
		if got := tr.usePerHop(); got != c.want {
			t.Errorf("%s: usePerHop() = %v, want %v", c.name, got, c.want)
		}
	}
}
