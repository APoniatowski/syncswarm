package transfer

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/APoniatowski/syncswarm/internal/discovery"
	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/fragment"
	"github.com/APoniatowski/syncswarm/internal/routing"
)

// reassemble concatenates chunks back into a single byte slice.
func reassemble(chunks [][]byte) []byte {
	var buf bytes.Buffer
	for _, c := range chunks {
		buf.Write(c)
	}
	return buf.Bytes()
}

func TestSplitReassembleRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		size      int
		chunkSize int
	}{
		{"empty", 0, 8},
		{"smaller-than-chunk", 5, 8},
		{"exact-multiple", 16, 8},
		{"with-remainder", 20, 8},
		{"single-byte-chunks", 7, 1},
		{"large", 1 << 16, 1024},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := make([]byte, tc.size)
			for i := range orig {
				orig[i] = byte(i * 31)
			}

			chunks := fragment.Split(orig, tc.chunkSize)

			// No chunk may exceed the chunk size.
			for i, c := range chunks {
				if len(c) > tc.chunkSize {
					t.Fatalf("chunk %d exceeds chunk size: %d > %d", i, len(c), tc.chunkSize)
				}
			}

			got := reassemble(chunks)
			if !bytes.Equal(got, orig) {
				t.Fatalf("reassembled bytes differ from original (len got=%d want=%d)", len(got), len(orig))
			}
		})
	}
}

// TestSealedRoundTrip builds sealed fragments the way the send path does and
// feeds them through the receive-side reassembly path, asserting the original
// payload is recovered.
func TestSealedRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x2a}, 32)
	sealer, err := encryption.NewAEADSealer(key)
	if err != nil {
		t.Fatalf("NewAEADSealer: %v", err)
	}

	data := make([]byte, 5000)
	for i := range data {
		data[i] = byte(i*7 + 3)
	}
	id := sha256.Sum256([]byte("sealed-round-trip"))

	fr, err := fragment.NewFragmenter(sealer, 512)
	if err != nil {
		t.Fatalf("NewFragmenter: %v", err)
	}
	frags, err := fr.Fragment(id, data)
	if err != nil {
		t.Fatalf("Fragment: %v", err)
	}
	if len(frags) == 0 {
		t.Fatal("expected at least one fragment")
	}

	// The sealed payloads must not equal the plaintext chunks.
	if bytes.Contains(bytes.Join(fragmentPayloads(frags), nil), data[:512]) {
		t.Fatal("sealed fragments unexpectedly contain plaintext")
	}

	// Simulate the receive side collecting chunks keyed by 0-based index.
	total := frags[0].Total
	chunks := make(map[uint32][]byte, len(frags))
	for _, f := range frags {
		chunks[f.Index] = f.Payload
	}

	got, err := reassembleChunks(sealer, id, total, chunks)
	if err != nil {
		t.Fatalf("reassembleChunks: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("sealed round-trip mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

// TestPlaintextRoundTrip covers the back-compat path where no sealer is set.
func TestPlaintextRoundTrip(t *testing.T) {
	data := []byte("the quick brown fox jumps over the lazy dog, repeatedly and thoroughly")
	id := sha256.Sum256([]byte("plaintext-round-trip"))

	raw := fragment.Split(data, 8)
	frags := make([]fragment.Fragment, len(raw))
	for i := range raw {
		frags[i] = fragment.Fragment{TransferID: id, Index: uint32(i), Total: uint32(len(raw)), Payload: raw[i]}
	}

	total := frags[0].Total
	chunks := make(map[uint32][]byte, len(frags))
	for _, f := range frags {
		// Plaintext payloads must equal the raw chunks.
		chunks[f.Index] = f.Payload
	}

	got, err := reassembleChunks(nil, id, total, chunks)
	if err != nil {
		t.Fatalf("reassembleChunks: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("plaintext round-trip mismatch: got %q, want %q", got, data)
	}
}

// TestNodesToPeersAndFastestRoute verifies the discovery.Node -> routing.Peer
// adapter maps fields correctly and that FastestRoute orders fastest-first.
func TestNodesToPeersAndFastestRoute(t *testing.T) {
	nodes := []*discovery.Node{
		{ID: "slow", Address: "10.0.0.3:64512", Latency: 300 * time.Millisecond, Active: true},
		{ID: "fast", Address: "10.0.0.1:64512", Latency: 50 * time.Millisecond, Active: true},
		{ID: "down", Address: "10.0.0.9:64512", Latency: 10 * time.Millisecond, Active: false},
		{ID: "mid", Address: "10.0.0.2:64512", Latency: 150 * time.Millisecond, Active: true},
	}

	peers := nodesToPeers(nodes)
	if len(peers) != len(nodes) {
		t.Fatalf("adapter dropped peers: got %d, want %d", len(peers), len(nodes))
	}
	for i, n := range nodes {
		p := peers[i]
		if p.ID != n.ID || p.Address != n.Address || p.Latency != n.Latency || p.Active != n.Active {
			t.Fatalf("field mismatch at %d: peer=%+v node=%+v", i, p, *n)
		}
	}

	ordered, err := (&routing.Planner{}).FastestRoute("fast", peers)
	if err != nil {
		t.Fatalf("FastestRoute: %v", err)
	}

	// Inactive "down" must be excluded; the rest ascending by latency.
	wantOrder := []string{"fast", "mid", "slow"}
	if len(ordered) != len(wantOrder) {
		t.Fatalf("expected %d active peers, got %d", len(wantOrder), len(ordered))
	}
	for i, id := range wantOrder {
		if ordered[i].ID != id {
			t.Fatalf("order mismatch at %d: got %q, want %q", i, ordered[i].ID, id)
		}
	}
}

func fragmentPayloads(frags []fragment.Fragment) [][]byte {
	out := make([][]byte, len(frags))
	for i, f := range frags {
		out[i] = f.Payload
	}
	return out
}
