package mobile

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

type capturingSink struct {
	mu      sync.Mutex
	data    [][]byte
	streams []string
	results map[string]string
}

func newSink() *capturingSink { return &capturingSink{results: map[string]string{}} }

func (s *capturingSink) OnData(d []byte) {
	s.mu.Lock()
	s.data = append(s.data, append([]byte(nil), d...))
	s.mu.Unlock()
}
func (s *capturingSink) OnStream(id, path string) {
	s.mu.Lock()
	s.streams = append(s.streams, path)
	s.mu.Unlock()
}
func (s *capturingSink) OnSendResult(token, errMsg string) {
	s.mu.Lock()
	s.results[token] = errMsg
	s.mu.Unlock()
}
func (s *capturingSink) gotData(want []byte, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		for _, got := range s.data {
			if bytes.Equal(got, want) {
				s.mu.Unlock()
				return true
			}
		}
		s.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func newNode(t *testing.T, sink EventSink, key []byte) *Node {
	t.Helper()
	n, err := NewNode(&Config{
		StorageDir: t.TempDir(), Key: key, Profile: "direct",
		DiscoveryPort: -1, DataPort: -1,
	}, sink)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if n.DiscoveryPort() == 0 || n.DataPort() == 0 {
		n.Stop()
		t.Skip("cannot bind ephemeral ports")
	}
	t.Cleanup(func() { n.Stop() })
	return n
}

// TestMobileBindingMessaging exercises the gomobile-shaped path end-to-end: two
// Nodes exchange a message and the recipient's EventSink receives it.
func TestMobileBindingMessaging(t *testing.T) {
	key := bytes.Repeat([]byte{0x8a}, 32)
	aSink, bSink := newSink(), newSink()
	a := newNode(t, aSink, key)
	b := newNode(t, bSink, key)

	a.SetBootstrapPeers(fmt.Sprintf("127.0.0.1:%d", b.DiscoveryPort()))
	b.SetBootstrapPeers(fmt.Sprintf("127.0.0.1:%d", a.DiscoveryPort()))

	// StatsJSON/PeerHealthJSON return valid JSON.
	if s := a.StatsJSON(); len(s) == 0 || s[0] != '{' {
		t.Fatalf("StatsJSON not JSON: %q", s)
	}

	payload := []byte("hello from the mobile binding")
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		a.Bootstrap()
		b.Bootstrap()
		time.Sleep(200 * time.Millisecond)

		a.SendToAsync(payload, b.NodeID(), "tok1")
		if bSink.gotData(payload, 1500*time.Millisecond) {
			return // delivered to the sink
		}
	}
	t.Fatal("timed out waiting for delivery to the mobile sink")
}
