// Package dht implements the Kademlia primitives SyncSwarm uses for structured,
// scalable peer discovery: 128-bit node IDs under an XOR metric, a k-bucket
// routing table, and the iterative node-lookup algorithm. It is transport-free
// and deterministic — the network (UDP FIND_NODE RPCs, bucket refresh) is driven
// by the discovery package, which supplies a query callback to Lookup.
package dht

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"sort"
	"sync"
)

const (
	// IDLen is the node-ID width in bytes. SyncSwarm node IDs are the first 16
	// bytes of the SHA-256 of a node's Ed25519 key (see protocol.DeriveNodeID),
	// hex-encoded; that 128-bit value is the Kademlia key.
	IDLen  = 16
	IDBits = IDLen * 8

	// DefaultK is the bucket size and lookup result-set width.
	DefaultK = 20
	// DefaultAlpha is the lookup query concurrency (nodes probed per round).
	DefaultAlpha = 3
	// DefaultMaxRounds bounds iterative-lookup rounds. Honest Kademlia converges
	// in O(log n) rounds — 20 rounds covers ~a million nodes — so this only caps
	// adversarial non-convergence, never a legitimate lookup.
	DefaultMaxRounds = 20
)

// ID is a 128-bit Kademlia key.
type ID [IDLen]byte

// ParseID decodes a hex node ID (as produced by protocol.DeriveNodeID). It
// requires exactly IDLen bytes (2*IDLen hex chars).
func ParseID(s string) (ID, error) {
	var id ID
	b, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("dht: bad hex id: %w", err)
	}
	if len(b) != IDLen {
		return id, fmt.Errorf("dht: id must be %d bytes, got %d", IDLen, len(b))
	}
	copy(id[:], b)
	return id, nil
}

// String returns the hex form of the ID.
func (id ID) String() string { return hex.EncodeToString(id[:]) }

// IsZero reports whether the ID is all zero.
func (id ID) IsZero() bool {
	for _, b := range id {
		if b != 0 {
			return false
		}
	}
	return true
}

// xor returns the bitwise XOR of a and b — the Kademlia distance value.
func xor(a, b ID) ID {
	var d ID
	for i := range d {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// less reports whether a < b as a 128-bit big-endian unsigned integer.
func less(a, b ID) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// closer reports whether a is strictly closer to target than b under XOR.
func closer(target, a, b ID) bool {
	return less(xor(a, target), xor(b, target))
}

// bucketIndex returns the index of the most-significant differing bit between
// self and other (0..IDBits-1, where IDBits-1 is the most-significant bit), or
// -1 if the IDs are identical. Nodes that differ only in low-order bits (close
// under XOR) land in low buckets; those differing high up land in high buckets.
func bucketIndex(self, other ID) int {
	d := xor(self, other)
	for i := 0; i < IDLen; i++ {
		if d[i] != 0 {
			// Most-significant set bit within byte i.
			msbInByte := 7 - bits.LeadingZeros8(d[i])
			byteFromLSB := (IDLen - 1 - i)
			return byteFromLSB*8 + msbInByte
		}
	}
	return -1
}

// Contact is a routable reference to a peer: its Kademlia ID plus the addresses
// the discovery/transfer layers need to reach it.
type Contact struct {
	ID      ID
	Address string // host:port for discovery RPCs (UDP)
	Port    uint16 // advertised transfer/data port
}

// RoutingTable is a Kademlia k-bucket routing table. Each bucket holds up to k
// contacts ordered oldest→newest; on a repeat sighting a contact moves to the
// newest position, and a full bucket evicts its oldest entry to admit a new one
// (a simplification of Kademlia's ping-the-oldest policy — the discovery layer
// prunes dead contacts separately).
type RoutingTable struct {
	mu      sync.Mutex
	self    ID
	k       int
	buckets [IDBits][]Contact
}

// NewRoutingTable returns a routing table for self with bucket size k (k<=0 uses
// DefaultK).
func NewRoutingTable(self ID, k int) *RoutingTable {
	if k <= 0 {
		k = DefaultK
	}
	return &RoutingTable{self: self, k: k}
}

// Self returns the table owner's ID.
func (rt *RoutingTable) Self() ID { return rt.self }

// Update records a sighting of c. The local node and zero IDs are ignored.
func (rt *RoutingTable) Update(c Contact) {
	if c.ID == rt.self || c.ID.IsZero() {
		return
	}
	bi := bucketIndex(rt.self, c.ID)
	if bi < 0 {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	b := rt.buckets[bi]
	for i := range b {
		if b[i].ID == c.ID {
			// Move to newest, refreshing address/port.
			b = append(b[:i], b[i+1:]...)
			b = append(b, c)
			rt.buckets[bi] = b
			return
		}
	}
	if len(b) >= rt.k {
		b = b[1:] // evict oldest
	}
	rt.buckets[bi] = append(b, c)
}

// Closest returns up to count contacts nearest to target, closest first.
func (rt *RoutingTable) Closest(target ID, count int) []Contact {
	rt.mu.Lock()
	all := make([]Contact, 0, rt.lenLocked())
	for i := range rt.buckets {
		all = append(all, rt.buckets[i]...)
	}
	rt.mu.Unlock()

	sort.Slice(all, func(i, j int) bool {
		return closer(target, all[i].ID, all[j].ID)
	})
	if count >= 0 && len(all) > count {
		all = all[:count]
	}
	return all
}

// Len returns the number of contacts held across all buckets.
func (rt *RoutingTable) Len() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.lenLocked()
}

func (rt *RoutingTable) lenLocked() int {
	n := 0
	for i := range rt.buckets {
		n += len(rt.buckets[i])
	}
	return n
}

// Lookup runs the iterative Kademlia node lookup for target and returns the up
// to k closest contacts it converged on, closest first. It starts from the
// table's own closest contacts and repeatedly probes the alpha closest not-yet-
// queried contacts via query, merging each reply's contacts, until the k closest
// have all been queried (or no unqueried contacts remain). query must return the
// contacts a probed node considers closest to target; a nil/empty return is fine
// (an unreachable node just yields nothing).
//
// maxRounds bounds the number of probe rounds (<=0 uses DefaultMaxRounds). Honest
// lookups converge in O(log n) rounds well under the cap; the cap is a backstop
// so a malicious peer that keeps returning fresh "closer" contacts cannot make a
// lookup run indefinitely.
func (rt *RoutingTable) Lookup(target ID, k, alpha, maxRounds int, query func(Contact) []Contact) []Contact {
	if k <= 0 {
		k = rt.k
	}
	if alpha <= 0 {
		alpha = DefaultAlpha
	}
	if maxRounds <= 0 {
		maxRounds = DefaultMaxRounds
	}

	shortlist := rt.Closest(target, k)
	queried := map[ID]bool{rt.self: true}
	seen := map[ID]bool{rt.self: true}
	for _, c := range shortlist {
		seen[c.ID] = true
	}

	for round := 0; round < maxRounds; round++ {
		// Select up to alpha closest contacts not yet queried.
		var batch []Contact
		for _, c := range shortlist {
			if len(batch) >= alpha {
				break
			}
			if !queried[c.ID] {
				batch = append(batch, c)
			}
		}
		if len(batch) == 0 {
			break // every contact in the k-closest shortlist has been queried
		}

		for _, c := range batch {
			queried[c.ID] = true
			for _, r := range query(c) {
				if seen[r.ID] {
					continue
				}
				seen[r.ID] = true
				shortlist = append(shortlist, r)
			}
		}

		sort.Slice(shortlist, func(i, j int) bool {
			return closer(target, shortlist[i].ID, shortlist[j].ID)
		})
		if len(shortlist) > k {
			shortlist = shortlist[:k]
		}
	}
	return shortlist
}
