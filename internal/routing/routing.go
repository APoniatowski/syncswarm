// Package routing selects paths for SyncSwarm fragments across the peer network.
//
// Today it provides two deterministic capabilities:
//
//   - Fastest-route selection: given a destination and a snapshot of peers,
//     order the active candidates fastest-first (ascending latency) so callers
//     can reach or relay toward the destination over the lowest-latency links.
//   - Spread planning: distribute fragment indices across MULTIPLE distinct
//     low-latency relays (onion-style spreading), so that no single relay ever
//     holds the whole payload.
//   - Tiered path selection (BuildPathTiered): choose an onion path that spreads
//     load across the fastest half of a node's relays and biases the exit toward
//     the destination, while staying anonymous — a fast pool with seeded, per-copy
//     shuffling rather than a single predictable "quickest" path.
//
// FastestRoute and BuildPath are deterministic (ties broken by Peer.ID).
// BuildPathTiered is deterministic *given its Seed*: the same seed yields the same
// path, but varying the seed per redundant copy spreads traffic across the pool.
package routing

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"time"
)

// Errors returned by the Planner.
var (
	// ErrNoActivePeers is returned when a plan is requested but no active peers
	// are available to route through.
	ErrNoActivePeers = errors.New("routing: no active peers available")
	// ErrInvalidFragmentCount is returned when fragmentCount is not positive.
	ErrInvalidFragmentCount = errors.New("routing: fragment count must be positive")
	// ErrInsufficientRelays is returned when a spread across multiple relays is
	// requested but fewer than two active peers exist.
	ErrInsufficientRelays = errors.New("routing: insufficient active relays to spread across")
	// ErrNoDestination is returned when BuildPath is given a destination without
	// an ID or public key (the final hop cannot be addressed).
	ErrNoDestination = errors.New("routing: destination missing ID or public key")
	// ErrInvalidHopCount is returned when BuildPath is given a negative hop count.
	ErrInvalidHopCount = errors.New("routing: hop count must be non-negative")
)

// Peer is routing's decoupled view of a network node (adapted from
// discovery.Node by callers). The routing package intentionally defines its own
// type so it does not depend on any other internal package.
type Peer struct {
	ID      string
	Address string
	Latency time.Duration
	Active  bool

	// PubKey is opaque key bytes carried through for later use by callers.
	PubKey []byte
	// Port is the peer's advertised data port.
	Port uint16
	// RelayCapable reports whether the peer will forward messages for others.
	RelayCapable bool
}

// Planner produces deterministic routing decisions from a snapshot of peers.
type Planner struct{}

// activeSorted returns the active peers ordered fastest-first: ascending
// Latency, with ties broken by ascending ID for stable, deterministic output.
func activeSorted(peers []Peer) []Peer {
	active := make([]Peer, 0, len(peers))
	for _, p := range peers {
		if p.Active {
			active = append(active, p)
		}
	}
	sort.SliceStable(active, func(i, j int) bool {
		if active[i].Latency != active[j].Latency {
			return active[i].Latency < active[j].Latency
		}
		return active[i].ID < active[j].ID
	})
	return active
}

// FastestRoute returns the active candidate peers ordered fastest-first
// (ascending latency, ties broken by lower ID) for reaching or relaying toward
// dest. If dest is itself a known active peer it is a valid endpoint and remains
// in the ordering. It returns ErrNoActivePeers when no active peers exist.
//
// The dest argument identifies the destination the caller wants to reach; the
// returned slice is the latency-ordered set of peers to route/relay through.
func (p *Planner) FastestRoute(dest string, peers []Peer) ([]Peer, error) {
	active := activeSorted(peers)
	if len(active) == 0 {
		return nil, ErrNoActivePeers
	}
	return active, nil
}

// SpreadPlan assigns each fragment index (0..fragmentCount-1) to a relay so that
// fragments are distributed across multiple distinct low-latency relays. It
// uses the fastest-first ordering and round-robins fragments across the
// min(minRelays, len(activePeers)) lowest-latency relays, so no single relay
// holds every fragment (given more than one relay is used).
//
// The returned map is keyed by fragment index and is deterministic for a given
// input. It returns:
//   - ErrInvalidFragmentCount if fragmentCount <= 0,
//   - ErrNoActivePeers if there are no active peers,
//   - ErrInsufficientRelays if minRelays > 1 but fewer than two active peers
//     exist (a multi-relay spread is impossible).
func (p *Planner) SpreadPlan(fragmentCount, minRelays int, peers []Peer) (map[int]Peer, error) {
	if fragmentCount <= 0 {
		return nil, ErrInvalidFragmentCount
	}

	active := activeSorted(peers)
	if len(active) == 0 {
		return nil, ErrNoActivePeers
	}
	if minRelays > 1 && len(active) < 2 {
		return nil, ErrInsufficientRelays
	}

	// Number of distinct relays to spread across: at least minRelays, but never
	// more than the relays we actually have. Guard a non-positive minRelays.
	relayCount := minRelays
	if relayCount < 1 {
		relayCount = 1
	}
	if relayCount > len(active) {
		relayCount = len(active)
	}

	relays := active[:relayCount]

	plan := make(map[int]Peer, fragmentCount)
	for i := 0; i < fragmentCount; i++ {
		plan[i] = relays[i%relayCount]
	}
	return plan, nil
}

// Hop is one step in an ordered forwarding path: the node to hand off to, its
// reachable address, and its public key (used by callers to address that hop).
type Hop struct {
	NodeID  string
	Address string
	PubKey  []byte
}

// BuildPath returns an ordered forwarding path: up to hopCount intermediate
// hops (chosen fastest-first from the eligible relays) followed by dest as the
// final hop. Selection is deterministic; ties are broken by ascending NodeID.
//
// Eligible intermediates are peers that are Active, RelayCapable, carry a
// non-empty PubKey, and are not dest itself. It returns:
//   - ErrNoDestination if dest has no ID or no PubKey,
//   - ErrInvalidHopCount if hopCount < 0,
//   - ErrInsufficientRelays if hopCount > 0 but no eligible intermediates exist.
//
// hopCount == 0 is valid and yields a single-hop path of just dest.
func (p *Planner) BuildPath(dest Peer, relays []Peer, hopCount int) ([]Hop, error) {
	if dest.ID == "" || len(dest.PubKey) == 0 {
		return nil, ErrNoDestination
	}
	if hopCount < 0 {
		return nil, ErrInvalidHopCount
	}

	eligible := make([]Peer, 0, len(relays))
	for _, r := range relays {
		if r.Active && r.RelayCapable && len(r.PubKey) > 0 && r.ID != dest.ID {
			eligible = append(eligible, r)
		}
	}
	if hopCount > 0 && len(eligible) == 0 {
		return nil, ErrInsufficientRelays
	}

	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].Latency != eligible[j].Latency {
			return eligible[i].Latency < eligible[j].Latency
		}
		return eligible[i].ID < eligible[j].ID
	})

	// Prefer relays in distinct network subnets from each other and from the
	// destination, so a single operator running many nodes on a few IP ranges
	// (a Sybil) is unlikely to control a whole path. Diversity is a preference,
	// not a hard rule: if there aren't enough distinct subnets we fill the
	// remaining hops rather than shorten the path.
	n := hopCount
	if n > len(eligible) {
		n = len(eligible)
	}

	usedSubnet := map[string]bool{subnetKey(dest.Address): true}
	picked := make([]Peer, 0, n)
	pickedID := make(map[string]bool, n)

	// Pass 1: fastest-first, one relay per new subnet.
	for _, r := range eligible {
		if len(picked) >= n {
			break
		}
		sk := subnetKey(r.Address)
		if usedSubnet[sk] {
			continue
		}
		usedSubnet[sk] = true
		picked = append(picked, r)
		pickedID[r.ID] = true
	}
	// Pass 2: fill any remaining hops (allowing shared subnets).
	for _, r := range eligible {
		if len(picked) >= n {
			break
		}
		if pickedID[r.ID] {
			continue
		}
		picked = append(picked, r)
		pickedID[r.ID] = true
	}

	path := make([]Hop, 0, n+1)
	for _, r := range picked {
		path = append(path, Hop{NodeID: r.ID, Address: r.Address, PubKey: r.PubKey})
	}
	path = append(path, Hop{NodeID: dest.ID, Address: dest.Address, PubKey: dest.PubKey})
	return path, nil
}

// subnetKey returns a coarse network grouping for an address: the IPv4 /24 or the
// IPv6 /48, or the raw host when it can't be parsed. Used to prefer path/table
// diversity across operators.
func subnetKey(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("v4:%d.%d.%d", v4[0], v4[1], v4[2])
	}
	return "v6:" + ip.Mask(net.CIDRMask(48, 128)).String()
}

// DistinctSubnetRelays counts eligible relays grouped into distinct subnets,
// excluding the destination's own subnet. This is the number of *independent*
// hops a path can achieve: a second relay in a subnet already on the path costs a
// full round trip but adds no independence, so it does not count.
func DistinctSubnetRelays(destAddr string, relays []Peer) int {
	seen := map[string]bool{subnetKey(destAddr): true}
	n := 0
	for _, r := range relays {
		if !r.Active || !r.RelayCapable || len(r.PubKey) == 0 {
			continue
		}
		sk := subnetKey(r.Address)
		if seen[sk] {
			continue
		}
		seen[sk] = true
		n++
	}
	return n
}

// AdaptiveHops chooses an onion path length from relay diversity: more distinct
// subnets means more independent hops, so the path is "as anonymous as the swarm
// currently allows". It returns 0 when the floor (minHops) cannot be met, so the
// caller fails closed rather than routing with too little anonymity — never a
// silent drop to a direct send.
//
//	distinct-subnet relays -> hops
//	0                      -> 0 (fail)
//	1                      -> 1 (that relay is entry and exit)
//	2-3                    -> 2 (entry knows sender, exit knows dest, neither both)
//	4+                     -> 3 (margin against one compromised middle relay)
//
// maxHops caps the result (practical max 3); minHops is a floor that fails rather
// than routing below it. A non-positive maxHops means the built-in cap of 3.
func AdaptiveHops(destAddr string, relays []Peer, minHops, maxHops int) int {
	distinct := DistinctSubnetRelays(destAddr, relays)
	var hops int
	switch {
	case distinct >= 4:
		hops = 3
	case distinct >= 2:
		hops = 2
	case distinct == 1:
		hops = 1
	default:
		return 0
	}
	cap := maxHops
	if cap <= 0 || cap > 3 {
		cap = 3
	}
	if hops > cap {
		hops = cap
	}
	if minHops > 0 && hops < minHops {
		return 0
	}
	return hops
}

// PathOptions tunes tiered path selection (BuildPathTiered).
type PathOptions struct {
	// Seed makes the in-tier shuffle deterministic per redundant copy, so load
	// spreads across the fast pool without collapsing onto one predictable path.
	Seed int64
	// Deprioritize holds host (IP or name) strings to use only as a last resort —
	// e.g. seed nodes, which should stay reserved for bootstrap rather than carry
	// general traffic.
	Deprioritize map[string]bool
	// ExitNear holds relay IDs known to be near the destination; the hop adjacent
	// to the destination is drawn from these when possible, so a fragment doesn't
	// take an absurd exit detour away from where it's going.
	ExitNear map[string]bool
}

// BuildPathTiered is BuildPath with load-spreading, anonymity-preserving relay
// selection. Instead of always taking the strict fastest relays (predictable), it
// splits eligible relays into a fast half (low latency) and a reserve half,
// shuffles within each (seeded, so it's deterministic per copy but spread across
// the pool), places deprioritized hosts last, keeps one-relay-per-subnet
// diversity, and biases the exit hop toward the destination via ExitNear. A node
// computes "fast" relative to itself, so paths stay regional without any global
// topology map.
func (p *Planner) BuildPathTiered(dest Peer, relays []Peer, hopCount int, opt PathOptions) ([]Hop, error) {
	if dest.ID == "" || len(dest.PubKey) == 0 {
		return nil, ErrNoDestination
	}
	if hopCount < 0 {
		return nil, ErrInvalidHopCount
	}

	eligible := make([]Peer, 0, len(relays))
	for _, r := range relays {
		if r.Active && r.RelayCapable && len(r.PubKey) > 0 && r.ID != dest.ID {
			eligible = append(eligible, r)
		}
	}
	if hopCount > 0 && len(eligible) == 0 {
		return nil, ErrInsufficientRelays
	}

	n := hopCount
	if n > len(eligible) {
		n = len(eligible)
	}

	ordered := tierOrder(eligible, opt)
	picked := selectDiverse(ordered, n, dest.Address)
	picked = biasExit(picked, ordered, opt.ExitNear)

	path := make([]Hop, 0, len(picked)+1)
	for _, r := range picked {
		path = append(path, Hop{NodeID: r.ID, Address: r.Address, PubKey: r.PubKey})
	}
	path = append(path, Hop{NodeID: dest.ID, Address: dest.Address, PubKey: dest.PubKey})
	return path, nil
}

// tierOrder returns eligible relays ordered as: fast half (shuffled) ++ reserve
// half (shuffled) ++ deprioritized (shuffled). The split is by median latency;
// shuffling within a tier spreads load and defeats predictability while keeping
// slow/reserved relays out of the preferred set.
func tierOrder(eligible []Peer, opt PathOptions) []Peer {
	main := make([]Peer, 0, len(eligible))
	var deprio []Peer
	for _, r := range eligible {
		if opt.Deprioritize[hostOf(r.Address)] {
			deprio = append(deprio, r)
		} else {
			main = append(main, r)
		}
	}
	sort.SliceStable(main, func(i, j int) bool {
		if main[i].Latency != main[j].Latency {
			return main[i].Latency < main[j].Latency
		}
		return main[i].ID < main[j].ID
	})
	fastN := (len(main) + 1) / 2 // fast half rounds up, so a lone relay is "fast"
	fast := append([]Peer(nil), main[:fastN]...)
	reserve := append([]Peer(nil), main[fastN:]...)

	// Deterministic, seeded shuffle for path diversity/load-spreading — not a
	// security primitive (path secrecy comes from onion layering, not this order).
	// #nosec G404
	rng := rand.New(rand.NewSource(opt.Seed))
	shufflePeers(fast, rng)
	shufflePeers(reserve, rng)
	shufflePeers(deprio, rng)

	out := make([]Peer, 0, len(eligible))
	out = append(out, fast...)
	out = append(out, reserve...)
	out = append(out, deprio...)
	return out
}

// selectDiverse picks up to n relays from an already-ordered candidate list,
// preferring one relay per distinct subnet (excluding the destination's), then
// filling remaining slots. Order within the input is respected, so tier ordering
// is preserved.
func selectDiverse(ordered []Peer, n int, destAddr string) []Peer {
	usedSubnet := map[string]bool{subnetKey(destAddr): true}
	picked := make([]Peer, 0, n)
	pickedID := make(map[string]bool, n)
	for _, r := range ordered {
		if len(picked) >= n {
			break
		}
		sk := subnetKey(r.Address)
		if usedSubnet[sk] {
			continue
		}
		usedSubnet[sk] = true
		picked = append(picked, r)
		pickedID[r.ID] = true
	}
	for _, r := range ordered {
		if len(picked) >= n {
			break
		}
		if pickedID[r.ID] {
			continue
		}
		picked = append(picked, r)
		pickedID[r.ID] = true
	}
	return picked
}

// biasExit ensures the hop adjacent to the destination (the last picked relay) is
// near the destination when possible: if a picked relay is in exitNear, it is
// moved to the exit slot; otherwise an eligible exitNear relay replaces the exit.
func biasExit(picked, ordered []Peer, exitNear map[string]bool) []Peer {
	if len(exitNear) == 0 || len(picked) == 0 {
		return picked
	}
	last := len(picked) - 1
	if exitNear[picked[last].ID] {
		return picked
	}
	// Prefer promoting an already-picked near-dest relay to the exit slot.
	for i, r := range picked {
		if exitNear[r.ID] {
			picked[i], picked[last] = picked[last], picked[i]
			return picked
		}
	}
	// Otherwise substitute an eligible near-dest relay not already on the path.
	inPath := make(map[string]bool, len(picked))
	for _, r := range picked {
		inPath[r.ID] = true
	}
	for _, r := range ordered {
		if exitNear[r.ID] && !inPath[r.ID] {
			picked[last] = r
			return picked
		}
	}
	return picked
}

func shufflePeers(peers []Peer, rng *rand.Rand) {
	rng.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })
}

// hostOf returns the host portion of a host:port address, or the address itself
// if it has no port.
func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
