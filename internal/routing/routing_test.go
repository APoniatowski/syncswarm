package routing

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func ids(peers []Peer) []string {
	out := make([]string, len(peers))
	for i, p := range peers {
		out[i] = p.ID
	}
	return out
}

func TestFastestRouteOrdersByLatency(t *testing.T) {
	var pl Planner
	peers := []Peer{
		{ID: "c", Latency: 30 * time.Millisecond, Active: true},
		{ID: "a", Latency: 10 * time.Millisecond, Active: true},
		{ID: "b", Latency: 20 * time.Millisecond, Active: true},
	}

	got, err := pl.FastestRoute("dest", peers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(ids(got), want) {
		t.Fatalf("order = %v, want %v", ids(got), want)
	}
}

func TestFastestRouteStableTieBreakByID(t *testing.T) {
	var pl Planner
	peers := []Peer{
		{ID: "z", Latency: 10 * time.Millisecond, Active: true},
		{ID: "m", Latency: 10 * time.Millisecond, Active: true},
		{ID: "a", Latency: 10 * time.Millisecond, Active: true},
	}

	got, err := pl.FastestRoute("dest", peers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"a", "m", "z"}
	if !reflect.DeepEqual(ids(got), want) {
		t.Fatalf("tie order = %v, want %v", ids(got), want)
	}
}

func TestFastestRouteIgnoresInactive(t *testing.T) {
	var pl Planner
	peers := []Peer{
		{ID: "a", Latency: 10 * time.Millisecond, Active: false},
		{ID: "b", Latency: 20 * time.Millisecond, Active: true},
		{ID: "c", Latency: 5 * time.Millisecond, Active: false},
	}

	got, err := pl.FastestRoute("dest", peers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"b"}
	if !reflect.DeepEqual(ids(got), want) {
		t.Fatalf("active-only = %v, want %v", ids(got), want)
	}
}

func TestFastestRouteNoActivePeers(t *testing.T) {
	var pl Planner
	peers := []Peer{
		{ID: "a", Active: false},
		{ID: "b", Active: false},
	}

	if _, err := pl.FastestRoute("dest", peers); !errors.Is(err, ErrNoActivePeers) {
		t.Fatalf("err = %v, want ErrNoActivePeers", err)
	}

	if _, err := pl.FastestRoute("dest", nil); !errors.Is(err, ErrNoActivePeers) {
		t.Fatalf("err = %v, want ErrNoActivePeers", err)
	}
}

func TestSpreadPlanDistributesAcrossDistinctRelays(t *testing.T) {
	var pl Planner
	peers := []Peer{
		{ID: "a", Latency: 10 * time.Millisecond, Active: true},
		{ID: "b", Latency: 20 * time.Millisecond, Active: true},
		{ID: "c", Latency: 30 * time.Millisecond, Active: true},
		{ID: "d", Latency: 40 * time.Millisecond, Active: true},
	}

	plan, err := pl.SpreadPlan(6, 3, peers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Every fragment index covered exactly once.
	if len(plan) != 6 {
		t.Fatalf("plan size = %d, want 6", len(plan))
	}
	for i := 0; i < 6; i++ {
		if _, ok := plan[i]; !ok {
			t.Fatalf("fragment %d missing from plan", i)
		}
	}

	// At least the requested number of distinct relays are used, and they are
	// the lowest-latency ones (a, b, c).
	distinct := map[string]bool{}
	for _, peer := range plan {
		distinct[peer.ID] = true
	}
	if len(distinct) < 3 {
		t.Fatalf("distinct relays = %d, want >= 3", len(distinct))
	}
	for id := range distinct {
		if id == "d" {
			t.Fatalf("used higher-latency relay d; want only fastest relays a,b,c")
		}
	}

	// No single relay holds all fragments.
	counts := map[string]int{}
	for _, peer := range plan {
		counts[peer.ID]++
	}
	for id, c := range counts {
		if c == 6 {
			t.Fatalf("relay %s holds all fragments", id)
		}
	}
}

func TestSpreadPlanDeterministic(t *testing.T) {
	var pl Planner
	peers := []Peer{
		{ID: "b", Latency: 20 * time.Millisecond, Active: true},
		{ID: "a", Latency: 10 * time.Millisecond, Active: true},
		{ID: "c", Latency: 30 * time.Millisecond, Active: true},
	}

	first, err := pl.SpreadPlan(7, 2, peers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := pl.SpreadPlan(7, 2, peers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("plans differ across runs:\n%v\n%v", first, second)
	}

	// Round-robin over the two fastest relays (a, b) by index.
	want := map[int]string{0: "a", 1: "b", 2: "a", 3: "b", 4: "a", 5: "b", 6: "a"}
	for i, id := range want {
		if first[i].ID != id {
			t.Fatalf("fragment %d -> %s, want %s", i, first[i].ID, id)
		}
	}
}

func TestSpreadPlanErrors(t *testing.T) {
	var pl Planner
	active2 := []Peer{
		{ID: "a", Active: true},
		{ID: "b", Active: true},
	}
	oneActive := []Peer{
		{ID: "a", Active: true},
		{ID: "b", Active: false},
	}

	if _, err := pl.SpreadPlan(0, 2, active2); !errors.Is(err, ErrInvalidFragmentCount) {
		t.Fatalf("fragmentCount=0 err = %v, want ErrInvalidFragmentCount", err)
	}
	if _, err := pl.SpreadPlan(-1, 2, active2); !errors.Is(err, ErrInvalidFragmentCount) {
		t.Fatalf("fragmentCount<0 err = %v, want ErrInvalidFragmentCount", err)
	}
	if _, err := pl.SpreadPlan(3, 1, []Peer{{ID: "a", Active: false}}); !errors.Is(err, ErrNoActivePeers) {
		t.Fatalf("no active err = %v, want ErrNoActivePeers", err)
	}
	if _, err := pl.SpreadPlan(3, 2, oneActive); !errors.Is(err, ErrInsufficientRelays) {
		t.Fatalf("minRelays>1 single active err = %v, want ErrInsufficientRelays", err)
	}

	// minRelays == 1 with a single active peer is allowed (no spread required).
	if _, err := pl.SpreadPlan(3, 1, oneActive); err != nil {
		t.Fatalf("minRelays=1 single active: unexpected error %v", err)
	}
}

func TestBuildPath(t *testing.T) {
	pl := &Planner{}
	dest := Peer{ID: "dest", Address: "d:1", Active: true, PubKey: []byte{9}}

	relays := []Peer{
		{ID: "r-slow", Address: "s:1", Latency: 50 * time.Millisecond, Active: true, RelayCapable: true, PubKey: []byte{1}},
		{ID: "r-fast", Address: "f:1", Latency: 10 * time.Millisecond, Active: true, RelayCapable: true, PubKey: []byte{2}},
		{ID: "r-mid", Address: "m:1", Latency: 30 * time.Millisecond, Active: true, RelayCapable: true, PubKey: []byte{3}},
		{ID: "inactive", Address: "x:1", Latency: 1 * time.Millisecond, Active: false, RelayCapable: true, PubKey: []byte{4}},
		{ID: "not-relay", Address: "y:1", Latency: 1 * time.Millisecond, Active: true, RelayCapable: false, PubKey: []byte{5}},
		{ID: "no-key", Address: "z:1", Latency: 1 * time.Millisecond, Active: true, RelayCapable: true},
		{ID: "dest", Address: "d:1", Latency: 1 * time.Millisecond, Active: true, RelayCapable: true, PubKey: []byte{9}},
	}

	path, err := pl.BuildPath(dest, relays, 2)
	if err != nil {
		t.Fatalf("BuildPath: %v", err)
	}
	// Two fastest eligible intermediates (fast, mid), then dest last. The
	// inactive, non-relay, keyless, and dest-as-relay entries are excluded.
	got := []string{path[0].NodeID, path[1].NodeID, path[2].NodeID}
	want := []string{"r-fast", "r-mid", "dest"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("path = %v, want %v", got, want)
	}
	if path[2].NodeID != "dest" || string(path[2].PubKey) != string([]byte{9}) {
		t.Fatalf("final hop must be dest with its pubkey, got %+v", path[2])
	}

	// hopCount larger than available intermediates: use all eligible (3) + dest.
	if p, _ := pl.BuildPath(dest, relays, 10); len(p) != 4 {
		t.Fatalf("hopCount>available: len=%d, want 4", len(p))
	}

	// hopCount == 0 -> just dest.
	p0, err := pl.BuildPath(dest, relays, 0)
	if err != nil || len(p0) != 1 || p0[0].NodeID != "dest" {
		t.Fatalf("hopCount=0: got %v err %v", p0, err)
	}

	// Deterministic tie-break by NodeID when latencies are equal.
	tie := []Peer{
		{ID: "b", Active: true, RelayCapable: true, Latency: 5, PubKey: []byte{1}},
		{ID: "a", Active: true, RelayCapable: true, Latency: 5, PubKey: []byte{1}},
	}
	tp, _ := pl.BuildPath(dest, tie, 2)
	if tp[0].NodeID != "a" || tp[1].NodeID != "b" {
		t.Fatalf("tie-break: got %s,%s want a,b", tp[0].NodeID, tp[1].NodeID)
	}

	// Error cases.
	if _, err := pl.BuildPath(Peer{ID: "", PubKey: []byte{1}}, relays, 1); !errors.Is(err, ErrNoDestination) {
		t.Fatalf("empty dest ID: want ErrNoDestination, got %v", err)
	}
	if _, err := pl.BuildPath(Peer{ID: "d"}, relays, 1); !errors.Is(err, ErrNoDestination) {
		t.Fatalf("keyless dest: want ErrNoDestination, got %v", err)
	}
	if _, err := pl.BuildPath(dest, relays, -1); !errors.Is(err, ErrInvalidHopCount) {
		t.Fatalf("negative hopCount: want ErrInvalidHopCount, got %v", err)
	}
	if _, err := pl.BuildPath(dest, []Peer{{ID: "x", Active: false}}, 1); !errors.Is(err, ErrInsufficientRelays) {
		t.Fatalf("no eligible relays: want ErrInsufficientRelays, got %v", err)
	}
}

func TestBuildPathSubnetDiversity(t *testing.T) {
	pl := &Planner{}
	dest := Peer{ID: "dest", Address: "10.9.9.9:1", Active: true, PubKey: []byte{9}}
	relays := []Peer{
		{ID: "a1", Address: "10.0.0.1:1", Latency: 10, Active: true, RelayCapable: true, PubKey: []byte{1}},
		{ID: "a2", Address: "10.0.0.2:1", Latency: 11, Active: true, RelayCapable: true, PubKey: []byte{1}}, // same /24 as a1
		{ID: "b1", Address: "10.1.0.1:1", Latency: 20, Active: true, RelayCapable: true, PubKey: []byte{1}},
	}
	// With 2 hops it must prefer distinct subnets: a1 (fastest) then b1, not a2.
	path, err := pl.BuildPath(dest, relays, 2)
	if err != nil {
		t.Fatal(err)
	}
	if path[0].NodeID != "a1" || path[1].NodeID != "b1" {
		t.Fatalf("diverse path = [%s %s], want [a1 b1]", path[0].NodeID, path[1].NodeID)
	}

	// Fallback: relays sharing a subnet (and the dest's) still fill the hops.
	same := []Peer{
		{ID: "s1", Address: "127.0.0.1:1", Latency: 10, Active: true, RelayCapable: true, PubKey: []byte{1}},
		{ID: "s2", Address: "127.0.0.1:2", Latency: 11, Active: true, RelayCapable: true, PubKey: []byte{1}},
	}
	p2, err := pl.BuildPath(Peer{ID: "d", Address: "127.0.0.1:9", PubKey: []byte{9}}, same, 2)
	if err != nil || len(p2) != 3 {
		t.Fatalf("fallback path len = %d (err %v), want 3", len(p2), err)
	}
}
