package routing

import (
	"testing"
	"time"
)

func rl(id, addr string, ms int) Peer {
	return Peer{ID: id, Address: addr, Latency: time.Duration(ms) * time.Millisecond,
		Active: true, RelayCapable: true, PubKey: []byte{1}}
}

var tieredDest = Peer{ID: "dest", Address: "203.0.113.9:1", PubKey: []byte{1}}

func hopIDs(hops []Hop) []string {
	out := make([]string, len(hops))
	for i, h := range hops {
		out[i] = h.NodeID
	}
	return out
}

func TestBuildPathTiered_PrefersFastHalf(t *testing.T) {
	// Two fast (low latency) + two slow relays, all distinct subnets. A 2-hop path
	// must be drawn from the fast half.
	relays := []Peer{
		rl("fast1", "10.0.1.1:1", 10),
		rl("fast2", "10.0.2.1:1", 20),
		rl("slow1", "10.0.3.1:1", 500),
		rl("slow2", "10.0.4.1:1", 600),
	}
	fast := map[string]bool{"fast1": true, "fast2": true}
	for seed := int64(0); seed < 20; seed++ {
		hops, err := (&Planner{}).BuildPathTiered(tieredDest, relays, 2, PathOptions{Seed: seed})
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range hopIDs(hops)[:2] { // last hop is dest
			if !fast[id] {
				t.Fatalf("seed %d: picked non-fast relay %q; path=%v", seed, id, hopIDs(hops))
			}
		}
	}
}

func TestBuildPathTiered_SeedsLast(t *testing.T) {
	// The seed host must not be chosen while a normal relay is available.
	relays := []Peer{
		rl("seednode", "116.202.82.93:1", 5), // fastest, but a seed
		rl("normal", "10.0.9.1:1", 50),
	}
	opt := PathOptions{Deprioritize: map[string]bool{"116.202.82.93": true}}
	for seed := int64(0); seed < 10; seed++ {
		opt.Seed = seed
		hops, err := (&Planner{}).BuildPathTiered(tieredDest, relays, 1, opt)
		if err != nil {
			t.Fatal(err)
		}
		if hops[0].NodeID != "normal" {
			t.Fatalf("seed %d: chose seed relay over a normal one: %v", seed, hopIDs(hops))
		}
	}
}

func TestBuildPathTiered_ExitBias(t *testing.T) {
	relays := []Peer{
		rl("a", "10.0.1.1:1", 10),
		rl("b", "10.0.2.1:1", 10),
		rl("nearDest", "10.0.3.1:1", 400), // slow, but near the destination
	}
	opt := PathOptions{ExitNear: map[string]bool{"nearDest": true}}
	for seed := int64(0); seed < 10; seed++ {
		opt.Seed = seed
		hops, err := (&Planner{}).BuildPathTiered(tieredDest, relays, 2, opt)
		if err != nil {
			t.Fatal(err)
		}
		exit := hops[len(hops)-2].NodeID // last relay before dest
		if exit != "nearDest" {
			t.Fatalf("seed %d: exit hop = %q, want nearDest; path=%v", seed, exit, hopIDs(hops))
		}
	}
}

func TestBuildPathTiered_Deterministic(t *testing.T) {
	relays := []Peer{
		rl("a", "10.0.1.1:1", 10), rl("b", "10.0.2.1:1", 20),
		rl("c", "10.0.3.1:1", 30), rl("d", "10.0.4.1:1", 40),
	}
	p1, _ := (&Planner{}).BuildPathTiered(tieredDest, relays, 3, PathOptions{Seed: 42})
	p2, _ := (&Planner{}).BuildPathTiered(tieredDest, relays, 3, PathOptions{Seed: 42})
	if got1, got2 := hopIDs(p1), hopIDs(p2); len(got1) != len(got2) {
		t.Fatal("length mismatch")
	} else {
		for i := range got1 {
			if got1[i] != got2[i] {
				t.Fatalf("same seed gave different paths: %v vs %v", got1, got2)
			}
		}
	}
}

func TestBuildPathTiered_SubnetDiversity(t *testing.T) {
	// Three relays in the SAME subnet + one in another; a 2-hop path must use two
	// distinct subnets.
	relays := []Peer{
		rl("x1", "10.0.1.1:1", 10), rl("x2", "10.0.1.2:1", 10), rl("x3", "10.0.1.3:1", 10),
		rl("y", "10.0.2.1:1", 10),
	}
	hops, err := (&Planner{}).BuildPathTiered(tieredDest, relays, 2, PathOptions{Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if subnetKey(hops[0].Address) == subnetKey(hops[1].Address) {
		t.Fatalf("both relay hops share a subnet: %v", hopIDs(hops))
	}
}

func TestBuildPathTiered_InsufficientRelays(t *testing.T) {
	if _, err := (&Planner{}).BuildPathTiered(tieredDest, nil, 1, PathOptions{}); err != ErrInsufficientRelays {
		t.Fatalf("want ErrInsufficientRelays, got %v", err)
	}
}
