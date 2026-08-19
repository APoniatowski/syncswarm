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
//
// All decisions are deterministic: there is no randomness, and ties are broken
// by Peer.ID so that the same input always yields the same plan.
//
// Planned next increment (out of scope for this pass): full multi-hop onion
// forwarding, where each fragment travels through a chain of relays carrying
// per-hop relay headers under layered sealing, so that each relay only learns
// the next hop and never the full path or payload. The current package chooses
// relays but does not yet construct those layered, per-hop forwarding headers.
package routing

import (
	"errors"
	"fmt"
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
