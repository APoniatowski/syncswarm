package transfer

import (
	"fmt"
	"testing"

	"github.com/APoniatowski/syncswarm/internal/routing"
)

func distinctRelays(n int) []routing.Peer {
	peers := make([]routing.Peer, n)
	for i := 0; i < n; i++ {
		peers[i] = routing.Peer{
			ID: fmt.Sprintf("r%d", i), Address: fmt.Sprintf("10.0.%d.1:1", i),
			Active: true, RelayCapable: true, PubKey: []byte{1},
		}
	}
	return peers
}

func TestPathsFor_Fixed(t *testing.T) {
	tr := &Transfer{redundancy: 2}
	if got := tr.pathsFor(distinctRelays(10), "203.0.113.9:1"); got != 2 {
		t.Fatalf("fixed redundancy: got %d, want 2", got)
	}
	// A zero fixed redundancy floors at 1.
	tr0 := &Transfer{redundancy: 0}
	if got := tr0.pathsFor(distinctRelays(5), "203.0.113.9:1"); got != 1 {
		t.Fatalf("zero redundancy: got %d, want 1", got)
	}
}

func TestPathsFor_AdaptiveScalesWithDiversity(t *testing.T) {
	tr := &Transfer{adaptiveRedundancy: true, minRedundancy: 1, maxRedundancy: 4}
	dest := "203.0.113.9:1"
	cases := []struct{ relays, want int }{
		{0, 1},  // no diversity -> floor
		{1, 1},  // one distinct subnet
		{3, 3},  // scales with diversity
		{4, 4},  // at the ceiling
		{50, 4}, // capped, not 50
	}
	for _, c := range cases {
		if got := tr.pathsFor(distinctRelays(c.relays), dest); got != c.want {
			t.Errorf("relays=%d: paths=%d, want %d", c.relays, got, c.want)
		}
	}
}

func TestPathsFor_FloorProtectsThinNetwork(t *testing.T) {
	// A floor of 2 means even a 1-relay swarm asks for 2 paths (capped later by the
	// actual relay count in newForwardCtx).
	tr := &Transfer{adaptiveRedundancy: true, minRedundancy: 2, maxRedundancy: 4}
	if got := tr.pathsFor(distinctRelays(1), "203.0.113.9:1"); got != 2 {
		t.Fatalf("floor: got %d, want 2", got)
	}
}

func TestPathsFor_DefaultCeiling(t *testing.T) {
	// maxRedundancy 0 -> defaultMaxRedundancy.
	tr := &Transfer{adaptiveRedundancy: true, minRedundancy: 1, maxRedundancy: 0}
	if got := tr.pathsFor(distinctRelays(50), "203.0.113.9:1"); got != defaultMaxRedundancy {
		t.Fatalf("default ceiling: got %d, want %d", got, defaultMaxRedundancy)
	}
}
