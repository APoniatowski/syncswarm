package storage

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	s, err := NewStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	return s
}

func testID(seed byte) [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = seed + byte(i)
	}
	return id
}

func TestSaveLoadChunkRoundTrip(t *testing.T) {
	s := newTestStorage(t)
	id := testID(7)

	meta := &ChunkMeta{
		ID:          id,
		TotalChunks: 2,
		ChunkSize:   16,
		Timestamp:   time.Now(),
		DestGroup:   "grp",
		DestNode:    "dst",
	}

	c1 := []byte("first-chunk")
	c2 := []byte("second-chunk")

	if err := s.SaveChunk(id, 1, c1, meta); err != nil {
		t.Fatalf("SaveChunk 1: %v", err)
	}
	if err := s.SaveChunk(id, 2, c2, meta); err != nil {
		t.Fatalf("SaveChunk 2: %v", err)
	}

	got1, err := s.LoadChunk(id, 1)
	if err != nil {
		t.Fatalf("LoadChunk 1: %v", err)
	}
	if !bytes.Equal(got1, c1) {
		t.Fatalf("chunk 1 mismatch: got %q want %q", got1, c1)
	}

	got2, err := s.LoadChunk(id, 2)
	if err != nil {
		t.Fatalf("LoadChunk 2: %v", err)
	}
	if !bytes.Equal(got2, c2) {
		t.Fatalf("chunk 2 mismatch: got %q want %q", got2, c2)
	}
}

func TestGetChunkMeta(t *testing.T) {
	s := newTestStorage(t)
	id := testID(20)

	meta := &ChunkMeta{
		ID:          id,
		TotalChunks: 5,
		ChunkSize:   32,
		Timestamp:   time.Now().Truncate(time.Second),
		DestGroup:   "g",
		DestNode:    "n",
	}

	if err := s.SaveChunk(id, 1, []byte("data"), meta); err != nil {
		t.Fatalf("SaveChunk: %v", err)
	}

	got, err := s.GetChunkMeta(id)
	if err != nil {
		t.Fatalf("GetChunkMeta: %v", err)
	}
	if got.ID != id {
		t.Fatalf("meta ID mismatch")
	}
	if got.TotalChunks != 5 || got.ChunkSize != 32 {
		t.Fatalf("meta fields mismatch: %+v", got)
	}
	if got.DestGroup != "g" || got.DestNode != "n" {
		t.Fatalf("meta dest mismatch: %+v", got)
	}
}

func TestCleanupOldChunks(t *testing.T) {
	s := newTestStorage(t)

	oldID := testID(1)
	freshID := testID(200)

	oldMeta := &ChunkMeta{
		ID:          oldID,
		TotalChunks: 1,
		ChunkSize:   4,
		Timestamp:   time.Now().Add(-2 * time.Hour),
	}
	freshMeta := &ChunkMeta{
		ID:          freshID,
		TotalChunks: 1,
		ChunkSize:   4,
		Timestamp:   time.Now(),
	}

	if err := s.SaveChunk(oldID, 1, []byte("old"), oldMeta); err != nil {
		t.Fatalf("SaveChunk old: %v", err)
	}
	if err := s.SaveChunk(freshID, 1, []byte("new"), freshMeta); err != nil {
		t.Fatalf("SaveChunk fresh: %v", err)
	}

	if err := s.CleanupOldChunks(time.Hour); err != nil {
		t.Fatalf("CleanupOldChunks: %v", err)
	}

	// Old entry should be gone.
	if _, err := s.GetChunkMeta(oldID); err == nil {
		t.Fatal("expected old chunk meta to be removed")
	}
	oldDir := filepath.Join(s.baseDir, chunksDir, hex.EncodeToString(oldID[:]))
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatalf("expected old chunk dir removed, stat err=%v", err)
	}

	// Fresh entry should remain.
	if _, err := s.GetChunkMeta(freshID); err != nil {
		t.Fatalf("expected fresh chunk meta to remain: %v", err)
	}
	got, err := s.LoadChunk(freshID, 1)
	if err != nil || !bytes.Equal(got, []byte("new")) {
		t.Fatalf("expected fresh chunk to remain, got %q err %v", got, err)
	}
}

// TestOfflineBlobRoundTrip persists held blobs for two recipients and reloads
// them, verifying the payloads, sequence numbers, and expiry survive intact.
func TestOfflineBlobRoundTrip(t *testing.T) {
	s := newTestStorage(t)
	exp := time.Now().Add(time.Hour).Round(0)

	if err := s.SaveOffline("alice", 1, []byte("m1"), exp); err != nil {
		t.Fatalf("SaveOffline: %v", err)
	}
	if err := s.SaveOffline("alice", 2, []byte("m2"), exp); err != nil {
		t.Fatalf("SaveOffline: %v", err)
	}
	if err := s.SaveOffline("bob", 3, []byte("b1"), exp); err != nil {
		t.Fatalf("SaveOffline: %v", err)
	}

	loaded, err := s.LoadOffline()
	if err != nil {
		t.Fatalf("LoadOffline: %v", err)
	}
	if len(loaded["alice"]) != 2 || len(loaded["bob"]) != 1 {
		t.Fatalf("loaded alice=%d bob=%d, want 2 and 1", len(loaded["alice"]), len(loaded["bob"]))
	}

	bySeq := map[uint64][]byte{}
	for _, e := range loaded["alice"] {
		bySeq[e.Seq] = e.Blob
		if e.Expiry.UnixNano() != exp.UnixNano() {
			t.Fatalf("expiry not preserved: got %v want %v", e.Expiry, exp)
		}
	}
	if !bytes.Equal(bySeq[1], []byte("m1")) || !bytes.Equal(bySeq[2], []byte("m2")) {
		t.Fatalf("alice blobs = %v, want seq1=m1 seq2=m2", bySeq)
	}
}

// TestOfflineBlobDelete covers per-blob and whole-node deletion.
func TestOfflineBlobDelete(t *testing.T) {
	s := newTestStorage(t)
	exp := time.Now().Add(time.Hour)
	for i, m := range []string{"a", "b", "c"} {
		if err := s.SaveOffline("n", uint64(i+1), []byte(m), exp); err != nil {
			t.Fatalf("SaveOffline: %v", err)
		}
	}

	if err := s.DeleteOffline("n", 2); err != nil {
		t.Fatalf("DeleteOffline: %v", err)
	}
	loaded, _ := s.LoadOffline()
	if len(loaded["n"]) != 2 {
		t.Fatalf("after per-blob delete: %d held, want 2", len(loaded["n"]))
	}

	// Deleting a missing blob is not an error.
	if err := s.DeleteOffline("n", 99); err != nil {
		t.Fatalf("DeleteOffline(missing): %v", err)
	}

	if err := s.DeleteOfflineNode("n"); err != nil {
		t.Fatalf("DeleteOfflineNode: %v", err)
	}
	loaded, _ = s.LoadOffline()
	if len(loaded["n"]) != 0 {
		t.Fatalf("after node delete: %d held, want 0", len(loaded["n"]))
	}
}

// TestLoadOfflineEmpty returns an empty map rather than erroring on a fresh store.
func TestLoadOfflineEmpty(t *testing.T) {
	s := newTestStorage(t)
	loaded, err := s.LoadOffline()
	if err != nil {
		t.Fatalf("LoadOffline on empty store: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("empty store returned %d entries", len(loaded))
	}
}
