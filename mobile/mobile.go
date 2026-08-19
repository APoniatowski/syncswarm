// Package mobile is the official gomobile-bindable facade over the SyncSwarm SDK.
// It exposes only types gomobile can bridge to Java/Kotlin (Android) and
// Swift/Objective-C (iOS): strings, ints, bools, []byte, errors, and callback
// interfaces. Lists/structs are returned as JSON strings; delivery and incoming
// data are delivered through an EventSink the host app implements.
//
// Build the bindings with:
//
//	gomobile bind -target=android -o syncswarm.aar        ./mobile
//	gomobile bind -target=ios     -o SyncSwarm.xcframework ./mobile
//
// Desktop apps do not need this — they import the swarmsync package directly and
// use its native channel/slice/function-callback API. Using this facade means an
// app never hand-writes one and mis-plumbs an Options field.
package mobile

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/APoniatowski/syncswarm/swarmsync"
)

// EventSink receives asynchronous notifications. The host app implements it; its
// methods are called on background goroutines, so marshal to the UI thread on the
// host side.
type EventSink interface {
	// OnData delivers an incoming message's raw bytes.
	OnData(data []byte)
	// OnStream reports a fully received streamed transfer written to path (its
	// transfer id is provided for correlation).
	OnStream(id string, path string)
	// OnSendResult reports the outcome of a SendToAsync call: errMsg is empty on
	// success, otherwise the error text. token echoes the value SendToAsync
	// returned so the host can correlate the result with its call.
	OnSendResult(token string, errMsg string)
}

// Config configures a Node. All fields are gomobile-bindable.
type Config struct {
	StorageDir    string // persistent identity + chunk/offline storage
	StreamDir     string // where received streamed transfers are written (defaults to StorageDir/streams)
	Key           []byte // optional 32-byte content key (shared-swarm confidentiality)
	Profile       string // privacy preset: "direct", "balanced", or "anonymous"
	Relay         bool   // forward traffic for others
	StoreForward  bool   // as a relay, hold messages for offline recipients
	AutoRelay     bool   // AutoNAT: auto-hold reservations when unreachable
	NeedsRelay    bool   // force circuit reservations (unconditionally behind NAT)
	Bootstrap     string // comma-separated host:port bootstrap peers
	DiscoveryPort int    // 0 = default, negative = ephemeral
	DataPort      int
	DataShards    int // enable Reed-Solomon / streaming (with Key); e.g. 4
	ParityShards  int // e.g. 2
}

// Node is a running SyncSwarm node with a mobile-friendly surface.
type Node struct {
	s         *swarmsync.SyncSwarm
	sink      EventSink
	streamDir string
}

// NewNode builds a node from cfg, delivering events to sink.
func NewNode(cfg *Config, sink EventSink) (*Node, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	streamDir := cfg.StreamDir
	if streamDir == "" {
		streamDir = filepath.Join(cfg.StorageDir, "streams")
	}
	if err := os.MkdirAll(streamDir, 0700); err != nil {
		return nil, err
	}

	n := &Node{sink: sink, streamDir: streamDir}

	opts := swarmsync.Preset(profileOf(cfg.Profile))
	opts.StorageDir = cfg.StorageDir
	opts.Key = cfg.Key
	opts.Relay = cfg.Relay
	opts.StoreForward = cfg.StoreForward
	opts.AutoRelay = cfg.AutoRelay
	opts.NeedsRelay = cfg.NeedsRelay
	opts.DiscoveryPort = cfg.DiscoveryPort
	opts.DataPort = cfg.DataPort
	opts.DataShards = cfg.DataShards
	opts.ParityShards = cfg.ParityShards
	if s := strings.TrimSpace(cfg.Bootstrap); s != "" {
		opts.BootstrapPeers = strings.Split(s, ",")
	}
	opts.OnDataReceived = func(b []byte) {
		if n.sink != nil {
			n.sink.OnData(b)
		}
	}
	opts.OnStreamReceived = n.streamSink

	s, err := swarmsync.New(opts)
	if err != nil {
		return nil, err
	}
	n.s = s
	return n, nil
}

func profileOf(p string) swarmsync.Profile {
	switch swarmsync.Profile(p) {
	case swarmsync.ProfileDirect, swarmsync.ProfileAnonymous:
		return swarmsync.Profile(p)
	default:
		return swarmsync.ProfileBalanced
	}
}

// streamSink writes an incoming streamed transfer to a file and notifies the host.
func (n *Node) streamSink(id [32]byte) io.WriteCloser {
	hexID := fmt.Sprintf("%x", id)
	path := filepath.Join(n.streamDir, hexID+".bin")
	f, err := os.Create(path)
	if err != nil {
		return nopWriteCloser{}
	}
	return &notifyingFile{f: f, node: n, id: hexID, path: path}
}

// Start brings the node online. Stop shuts it down.
func (n *Node) Start() error { return n.s.Start() }
func (n *Node) Stop() error  { return n.s.Stop() }

// NodeID is this node's self-authenticating address; DiscoveryPort/DataPort
// report the bound transport ports.
func (n *Node) NodeID() string     { return n.s.NodeID() }
func (n *Node) DiscoveryPort() int { return n.s.DiscoveryPort() }
func (n *Node) DataPort() int      { return n.s.DataPort() }

// SetBootstrapPeers updates the peer list (comma-separated host:port); Bootstrap
// re-announces to them.
func (n *Node) SetBootstrapPeers(csv string) {
	var peers []string
	if s := strings.TrimSpace(csv); s != "" {
		peers = strings.Split(s, ",")
	}
	n.s.SetBootstrapPeers(peers)
}
func (n *Node) Bootstrap() { n.s.Bootstrap() }

// SendTo sends data to a node (blocks under confirmed delivery).
func (n *Node) SendTo(data []byte, nodeID string) error { return n.s.SendTo(data, nodeID) }

// SendToAsync sends without blocking; the outcome is reported via
// EventSink.OnSendResult with the provided token echoed back.
func (n *Node) SendToAsync(data []byte, nodeID, token string) {
	n.s.SendToAsync(data, nodeID, func(err error) {
		if n.sink == nil {
			return
		}
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		n.sink.OnSendResult(token, msg)
	})
}

// SendFile streams a file from path to a node (end-to-end, memory-bounded).
func (n *Node) SendFile(path, nodeID string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return n.s.SendStream(f, nodeID)
}

// FindNode locates a peer by ID via the DHT (usually unnecessary — SendTo
// resolves transparently). StatsJSON / PeerHealthJSON return diagnostics as JSON.
func (n *Node) FindNode(nodeID string) bool { return n.s.FindNode(nodeID) }
func (n *Node) StatsJSON() string           { b, _ := json.Marshal(n.s.Stats()); return string(b) }
func (n *Node) PeerHealthJSON() string      { b, _ := json.Marshal(n.s.PeerHealth()); return string(b) }

// notifyingFile writes stream blocks to a file and, on Close, tells the host.
type notifyingFile struct {
	f    *os.File
	node *Node
	id   string
	path string
}

func (w *notifyingFile) Write(p []byte) (int, error) { return w.f.Write(p) }
func (w *notifyingFile) Close() error {
	err := w.f.Close()
	if w.node.sink != nil {
		w.node.sink.OnStream(w.id, w.path)
	}
	return err
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }
