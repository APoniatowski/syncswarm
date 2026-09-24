package routing

import (
	"fmt"
	"testing"
)

func relay(addr string) Peer {
	return Peer{ID: addr, Address: addr, Active: true, RelayCapable: true, PubKey: []byte{1}}
}

func TestDistinctSubnetRelays(t *testing.T) {
	dest := "203.0.113.9:64512"
	cases := []struct {
		name   string
		relays []Peer
		want   int
	}{
		{"none", nil, 0},
		{"one", []Peer{relay("198.51.100.1:1")}, 1},
		{"three distinct", []Peer{relay("198.51.100.1:1"), relay("192.0.2.1:1"), relay("10.0.0.1:1")}, 3},
		{"same subnet collapses", []Peer{relay("198.51.100.1:1"), relay("198.51.100.2:1"), relay("198.51.100.3:1")}, 1},
		{"dest subnet excluded", []Peer{relay("203.0.113.5:1"), relay("192.0.2.1:1")}, 1},
	}
	for _, c := range cases {
		if got := DistinctSubnetRelays(dest, c.relays); got != c.want {
			t.Errorf("%s: DistinctSubnetRelays = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestDistinctSubnetRelays_SkipsIneligible(t *testing.T) {
	dest := "203.0.113.9:1"
	relays := []Peer{
		{Address: "198.51.100.1:1", Active: false, RelayCapable: true, PubKey: []byte{1}}, // inactive
		{Address: "192.0.2.1:1", Active: true, RelayCapable: false, PubKey: []byte{1}},    // not relay
		{Address: "10.0.0.1:1", Active: true, RelayCapable: true, PubKey: nil},            // no key
		relay("172.16.0.1:1"), // the only eligible one
	}
	if got := DistinctSubnetRelays(dest, relays); got != 1 {
		t.Fatalf("got %d eligible distinct subnets, want 1", got)
	}
}

func TestAdaptiveHops(t *testing.T) {
	dest := "203.0.113.9:1"
	mk := func(n int) []Peer {
		peers := make([]Peer, n)
		for i := 0; i < n; i++ {
			peers[i] = relay(fmt.Sprintf("10.0.%d.1:1", i)) // each in a distinct /24
		}
		return peers
	}
	cases := []struct {
		name           string
		n              int
		min, max, want int
	}{
		{"zero -> fail", 0, 0, 0, 0},
		{"one -> 1", 1, 0, 0, 1},
		{"two -> 2", 2, 0, 0, 2},
		{"three -> 2", 3, 0, 0, 2},
		{"four -> 3", 4, 0, 0, 3},
		{"six -> 3 (cap)", 6, 0, 0, 3},
		{"max caps to 1", 6, 0, 1, 1},
		{"min floor fails", 1, 2, 0, 0}, // distinct 1 -> 1 hop, below floor 2 -> fail
		{"min met", 4, 3, 0, 3},
	}
	for _, c := range cases {
		if got := AdaptiveHops(dest, mk(c.n), c.min, c.max); got != c.want {
			t.Errorf("%s: AdaptiveHops(n=%d,min=%d,max=%d) = %d, want %d", c.name, c.n, c.min, c.max, got, c.want)
		}
	}
}
