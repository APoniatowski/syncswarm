package discovery

import (
	"encoding/json"
	"os"
	"sort"
)

// maxCachedPeers bounds how many peer addresses are persisted, keeping the cache
// small and biased toward the most recently seen peers.
const maxCachedPeers = 64

// SetPeerCache enables persistent peer caching at path and immediately loads any
// previously cached peer addresses into the bootstrap set, so a restarted node
// re-contacts peers it already knew instead of relying solely on the seed. Call
// before Start.
func (d *Discovery) SetPeerCache(path string) {
	if path == "" {
		return
	}
	d.peerCachePath = path
	for _, addr := range d.loadPeerCache() {
		d.addBootstrap(addr)
	}
}

// addBootstrap appends addr to the bootstrap set if not already present.
func (d *Discovery) addBootstrap(addr string) {
	if addr == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, a := range d.bootstrapPeers {
		if a == addr {
			return
		}
	}
	d.bootstrapPeers = append(d.bootstrapPeers, addr)
}

// loadPeerCache reads the persisted peer addresses, or nil if none/unreadable.
func (d *Discovery) loadPeerCache() []string {
	if d.peerCachePath == "" {
		return nil
	}
	data, err := os.ReadFile(d.peerCachePath)
	if err != nil {
		return nil
	}
	var addrs []string
	if err := json.Unmarshal(data, &addrs); err != nil {
		return nil
	}
	return addrs
}

// savePeerCache writes the most recently seen active peer addresses to disk
// (atomically), bounded to maxCachedPeers. Cheap and best-effort: errors are
// ignored so a read-only or full disk never disrupts discovery.
func (d *Discovery) savePeerCache() {
	if d.peerCachePath == "" {
		return
	}

	type seen struct {
		addr string
		last int64
	}
	d.mu.RLock()
	peers := make([]seen, 0, len(d.nodes))
	for _, n := range d.nodes {
		if n.Address == "" {
			continue
		}
		peers = append(peers, seen{addr: n.Address, last: n.LastSeen.UnixNano()})
	}
	d.mu.RUnlock()

	// Most recently seen first, then cap.
	sort.Slice(peers, func(i, j int) bool { return peers[i].last > peers[j].last })
	if len(peers) > maxCachedPeers {
		peers = peers[:maxCachedPeers]
	}
	addrs := make([]string, 0, len(peers))
	for _, p := range peers {
		addrs = append(addrs, p.addr)
	}

	data, err := json.Marshal(addrs)
	if err != nil {
		return
	}
	tmp := d.peerCachePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, d.peerCachePath) // atomic replace
}
