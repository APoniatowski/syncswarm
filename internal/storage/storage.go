package storage

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/APoniatowski/syncswarm/internal/discovery"
)

const (
	nodesDir   = "nodes"    // Directory for storing node information
	chunksDir  = "chunks"   // Directory for storing data chunks
	metaDir    = "metadata" // Directory for chunk metadata
	offlineDir = "offline"  // Directory for store-and-forward blobs held for offline recipients
)

// Storage handles persistent storage of nodes and data chunks using the filesystem
type Storage struct {
	baseDir string
	mu      sync.RWMutex
}

// ChunkMeta contains metadata about stored chunks
type ChunkMeta struct {
	ID          [32]byte  `json:"id"`
	TotalChunks uint32    `json:"total_chunks"`
	ChunkSize   uint32    `json:"chunk_size"`
	Timestamp   time.Time `json:"timestamp"`
	DestGroup   string    `json:"dest_group"`
	DestNode    string    `json:"dest_node"`
}

// NewStorage creates a new storage instance
func NewStorage(baseDir string) (*Storage, error) {
	// Create required directories
	dirs := []string{
		filepath.Join(baseDir, nodesDir),
		filepath.Join(baseDir, chunksDir),
		filepath.Join(baseDir, metaDir),
		filepath.Join(baseDir, offlineDir),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return &Storage{
		baseDir: baseDir,
	}, nil
}

// OfflineBlob is a store-and-forward payload held on disk for an offline
// recipient, tagged with the sequence number that names its file and the
// expiry after which it may be swept.
type OfflineBlob struct {
	Seq    uint64
	Blob   []byte
	Expiry time.Time
}

// offlineNodeDir returns the on-disk directory holding blobs for nodeID. The
// node identifier is hex-encoded so any identifier is a safe path component.
func (s *Storage) offlineNodeDir(nodeID string) string {
	return filepath.Join(s.baseDir, offlineDir, hex.EncodeToString([]byte(nodeID)))
}

// SaveOffline persists a single held blob for nodeID under the given sequence
// number. The file stores the expiry (8-byte big-endian unix-nano) followed by
// the raw blob, so it can be reloaded intact after a relay restart.
func (s *Storage) SaveOffline(nodeID string, seq uint64, blob []byte, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := s.offlineNodeDir(nodeID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create offline dir: %w", err)
	}
	buf := make([]byte, 8+len(blob))
	binary.BigEndian.PutUint64(buf[:8], uint64(expiry.UnixNano()))
	copy(buf[8:], blob)
	path := filepath.Join(dir, fmt.Sprintf("%d.blob", seq))
	if err := os.WriteFile(path, buf, 0644); err != nil {
		return fmt.Errorf("failed to write offline blob: %w", err)
	}
	return nil
}

// DeleteOffline removes a single held blob (e.g. after it expires).
func (s *Storage) DeleteOffline(nodeID string, seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.offlineNodeDir(nodeID), fmt.Sprintf("%d.blob", seq))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DeleteOfflineNode removes every held blob for nodeID (e.g. after they are all
// flushed or redelivered).
func (s *Storage) DeleteOfflineNode(nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.RemoveAll(s.offlineNodeDir(nodeID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// LoadOffline reads every persisted held blob back into memory, keyed by
// recipient node ID. Corrupt or unparseable files are skipped rather than
// failing the whole load. Returns an empty map if nothing is stored.
func (s *Storage) LoadOffline() (map[string][]OfflineBlob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	root := filepath.Join(s.baseDir, offlineDir)
	nodeDirs, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]OfflineBlob{}, nil
		}
		return nil, err
	}

	out := make(map[string][]OfflineBlob)
	for _, nd := range nodeDirs {
		if !nd.IsDir() {
			continue
		}
		idBytes, err := hex.DecodeString(nd.Name())
		if err != nil {
			continue
		}
		nodeID := string(idBytes)
		files, err := os.ReadDir(filepath.Join(root, nd.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".blob" {
				continue
			}
			var seq uint64
			if _, err := fmt.Sscanf(f.Name(), "%d.blob", &seq); err != nil {
				continue
			}
			data, err := os.ReadFile(filepath.Join(root, nd.Name(), f.Name()))
			if err != nil || len(data) < 8 {
				continue
			}
			expiry := time.Unix(0, int64(binary.BigEndian.Uint64(data[:8])))
			out[nodeID] = append(out[nodeID], OfflineBlob{
				Seq:    seq,
				Blob:   append([]byte(nil), data[8:]...),
				Expiry: expiry,
			})
		}
	}
	return out, nil
}

// SaveNode persists a node to storage
func (s *Storage) SaveNode(node *discovery.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(node)
	if err != nil {
		return fmt.Errorf("failed to marshal node: %w", err)
	}

	filename := filepath.Join(s.baseDir, nodesDir, node.ID+".json")
	return os.WriteFile(filename, data, 0644)
}

// LoadNodes retrieves all stored nodes
func (s *Storage) LoadNodes() ([]*discovery.Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := filepath.Join(s.baseDir, nodesDir)
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var nodes []*discovery.Node
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			continue // Skip files we can't read
		}

		var node discovery.Node
		if err := json.Unmarshal(data, &node); err != nil {
			continue // Skip malformed files
		}

		nodes = append(nodes, &node)
	}

	return nodes, nil
}

// SaveChunk stores a chunk of data
func (s *Storage) SaveChunk(id [32]byte, chunkNum uint32, data []byte, meta *ChunkMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hexID := hex.EncodeToString(id[:])

	// Create chunk directory if it doesn't exist
	chunkDir := filepath.Join(s.baseDir, chunksDir, hexID)
	if err := os.MkdirAll(chunkDir, 0755); err != nil {
		return err
	}

	// Save chunk data
	chunkPath := filepath.Join(chunkDir, fmt.Sprintf("%d.chunk", chunkNum))
	if err := os.WriteFile(chunkPath, data, 0644); err != nil {
		return err
	}

	// Save metadata if this is the first chunk
	if chunkNum == 1 {
		metaPath := filepath.Join(s.baseDir, metaDir, hexID+".json")
		metaData, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		return os.WriteFile(metaPath, metaData, 0644)
	}

	return nil
}

// LoadChunk retrieves a specific chunk of data
func (s *Storage) LoadChunk(id [32]byte, chunkNum uint32) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hexID := hex.EncodeToString(id[:])
	chunkPath := filepath.Join(s.baseDir, chunksDir, hexID, fmt.Sprintf("%d.chunk", chunkNum))
	return os.ReadFile(chunkPath)
}

// GetChunkMeta retrieves metadata for a specific data set
func (s *Storage) GetChunkMeta(id [32]byte) (*ChunkMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metaPath := filepath.Join(s.baseDir, metaDir, hex.EncodeToString(id[:])+".json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var meta ChunkMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// CleanupOldChunks removes chunks older than the specified duration
func (s *Storage) CleanupOldChunks(maxAge time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	metaDir := filepath.Join(s.baseDir, metaDir)
	files, err := os.ReadDir(metaDir)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		metaPath := filepath.Join(metaDir, file.Name())
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var meta ChunkMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}

		if now.Sub(meta.Timestamp) > maxAge {
			// Delete metadata file
			os.Remove(metaPath)

			// Delete chunk directory and all its contents
			chunkDir := filepath.Join(s.baseDir, chunksDir, hex.EncodeToString(meta.ID[:]))
			os.RemoveAll(chunkDir)
		}
	}

	return nil
}
