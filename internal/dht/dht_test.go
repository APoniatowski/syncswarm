package dht

import (
	"crypto/sha256"
	"testing"
)

// mkID deterministically derives a node ID from a seed, so tests are reproducible.
func mkID(seed int) ID {
	h := sha256.Sum256([]byte{byte(seed), byte(seed >> 8), byte(seed >> 16)})
	var id ID
	copy(id[:], h[:IDLen])
	return id
}

func TestParseIDRoundTrip(t *testing.T) {
	id := mkID(42)
	got, err := ParseID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("ParseID round-trip mismatch")
	}
	if _, err := ParseID("xyz"); err == nil {
		t.Fatal("ParseID must reject non-hex")
	}
	if _, err := ParseID("00ff"); err == nil {
		t.Fatal("ParseID must reject wrong length")
	}
}

func TestBucketIndex(t *testing.T) {
	var self ID // all zero
	// Differ only in the least-significant bit -> bucket 0.
	other := self
	other[IDLen-1] = 0x01
	if bi := bucketIndex(self, other); bi != 0 {
		t.Fatalf("LSB difference: bucket = %d, want 0", bi)
	}
	// Differ in the most-significant bit -> bucket IDBits-1.
	other = self
	other[0] = 0x80
	if bi := bucketIndex(self, other); bi != IDBits-1 {
		t.Fatalf("MSB difference: bucket = %d, want %d", bi, IDBits-1)
	}
	// Identical -> -1.
	if bi := bucketIndex(self, self); bi != -1 {
		t.Fatalf("identical ids: bucket = %d, want -1", bi)
	}
}

func TestCloserMetric(t *testing.T) {
	target := mkID(1)
	a := mkID(1) // == target, distance 0
	b := mkID(2)
	if !closer(target, a, b) {
		t.Fatal("the target itself must be closest")
	}
	if closer(target, b, a) {
		t.Fatal("closer must be asymmetric for distinct distances")
	}
}

func TestRoutingTableUpdateAndSelf(t *testing.T) {
	self := mkID(0)
	rt := NewRoutingTable(self, 20)

	// Self and zero IDs are ignored.
	rt.Update(Contact{ID: self, Address: "x"})
	rt.Update(Contact{ID: ID{}, Address: "x"})
	if rt.Len() != 0 {
		t.Fatalf("self/zero updates must be ignored, Len=%d", rt.Len())
	}

	c := Contact{ID: mkID(5), Address: "1.1.1.1:1"}
	rt.Update(c)
	rt.Update(Contact{ID: mkID(5), Address: "2.2.2.2:2"}) // repeat refreshes, no dup
	if rt.Len() != 1 {
		t.Fatalf("repeat sighting must not duplicate, Len=%d", rt.Len())
	}
	got := rt.Closest(mkID(5), 1)
	if len(got) != 1 || got[0].Address != "2.2.2.2:2" {
		t.Fatalf("repeat sighting must refresh address, got %+v", got)
	}
}

func TestBucketEviction(t *testing.T) {
	// A single bucket holds the most-recent k. Build IDs that all share the same
	// bucket relative to self by differing from self only within the same bit
	// position range is hard; instead use a tiny k and rely on many random IDs
	// landing in the top bucket.
	self := mkID(0)
	rt := NewRoutingTable(self, 4)
	for i := 1; i <= 200; i++ {
		rt.Update(Contact{ID: mkID(i), Address: "a"})
	}
	// No bucket may exceed k.
	rt.mu.Lock()
	for i := range rt.buckets {
		if len(rt.buckets[i]) > rt.k {
			rt.mu.Unlock()
			t.Fatalf("bucket %d has %d contacts, exceeds k=%d", i, len(rt.buckets[i]), rt.k)
		}
	}
	rt.mu.Unlock()
}

func TestClosestOrdering(t *testing.T) {
	self := mkID(0)
	rt := NewRoutingTable(self, 20)
	for i := 1; i <= 50; i++ {
		rt.Update(Contact{ID: mkID(i), Address: "a"})
	}
	target := mkID(7)
	got := rt.Closest(target, 5)
	if len(got) != 5 {
		t.Fatalf("Closest returned %d, want 5", len(got))
	}
	for i := 1; i < len(got); i++ {
		if closer(target, got[i].ID, got[i-1].ID) {
			t.Fatalf("Closest not sorted by distance at index %d", i)
		}
	}
	// The target itself, if known, must be first.
	if got[0].ID != target {
		t.Fatalf("nearest to a known target must be the target itself")
	}
}

// TestIterativeLookupConverges builds a synthetic network where each node knows
// the others through its own k-bucket table, and verifies the iterative lookup
// walks from a sparse seed to the exact target.
func TestIterativeLookupConverges(t *testing.T) {
	const n = 64
	contacts := make([]Contact, n)
	tables := make([]*RoutingTable, n)
	for i := 0; i < n; i++ {
		contacts[i] = Contact{ID: mkID(i + 1), Address: "node", Port: uint16(i)}
	}
	for i := 0; i < n; i++ {
		tables[i] = NewRoutingTable(contacts[i].ID, DefaultK)
		for j := 0; j < n; j++ {
			if i != j {
				tables[i].Update(contacts[j])
			}
		}
	}

	byID := make(map[ID]int, n)
	for i, c := range contacts {
		byID[c.ID] = i
	}
	// A probed node answers with what it knows closest to the target.
	query := func(c Contact) []Contact {
		idx, ok := byID[c.ID]
		if !ok {
			return nil
		}
		return tables[idx].Closest(lookupTarget, DefaultK)
	}

	// Searcher starts from node 0's table; look up every other node.
	searcher := tables[0]
	for tgt := 1; tgt < n; tgt++ {
		lookupTarget = contacts[tgt].ID
		res := searcher.Lookup(lookupTarget, DefaultK, DefaultAlpha, 0, query)
		if len(res) == 0 || res[0].ID != lookupTarget {
			t.Fatalf("lookup for node %d did not converge on the target (got %d results)", tgt, len(res))
		}
	}
}

// TestLookupBoundsRounds ensures a misbehaving peer that keeps returning fresh
// "closer" contacts cannot make a lookup run forever: the round cap holds.
func TestLookupBoundsRounds(t *testing.T) {
	self := mkID(0)
	rt := NewRoutingTable(self, DefaultK)
	target := mkID(999999)
	rt.Update(Contact{ID: mkID(1), Address: "seed"})

	rounds := 0
	seedCounter := 1000
	// Every probed node answers with a brand-new contact strictly closer to the
	// target, so the shortlist never "settles" — only the cap stops the loop.
	query := func(c Contact) []Contact {
		rounds++
		seedCounter++
		// Fabricate an ID that shares a long prefix with target (very close).
		closeID := target
		closeID[IDLen-1] ^= byte(seedCounter) // perturb only the last byte
		return []Contact{{ID: closeID, Address: "adversary"}}
	}

	rt.Lookup(target, DefaultK, 1, 5, query)
	if rounds > 5 {
		t.Fatalf("lookup ran %d rounds, must be bounded by maxRounds=5", rounds)
	}
}

// lookupTarget is set by the convergence test before each query closure call.
var lookupTarget ID
