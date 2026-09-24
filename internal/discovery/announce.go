package discovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/APoniatowski/syncswarm/internal/iface"
	"github.com/APoniatowski/syncswarm/internal/link"
	"github.com/APoniatowski/syncswarm/internal/protocol"
)

const (
	// announceHopMax bounds how far an announce floods (Reticulum's m+1 with
	// m=128): an announce that has already travelled this many hops is not
	// forwarded again.
	announceHopMax = 128
	// announceSpreadMax bounds the randomized delay before re-flooding an
	// announce, so a burst of transport nodes don't all retransmit at once.
	announceSpreadMax = 200 * time.Millisecond
	// announceDedupTTL is how long a (DestHash,Nonce) is remembered to suppress
	// re-forwarding the same announce during a flood.
	announceDedupTTL = 5 * time.Minute
	// maxPaths bounds the path table (LRU by last-seen), the "reasonable amount
	// of routes" cap.
	maxPaths = 4096
)

// pathEntry is the best known way to reach a destination hash: the interface and
// next-hop address the announce arrived from, and how many hops away it was.
type pathEntry struct {
	Iface    string
	NextHop  string // medium-specific address of the peer we heard it from
	Hops     uint8
	LastSeen time.Time
	OriginTS int64                     // announcer's Timestamp, for freshness comparison
	Ann      *protocol.AnnouncePayload // cached announce, re-flooded to answer path requests
}

// pathTable maps destination hash -> best known path. Bounded and LRU-evicted.
type pathTable struct {
	mu      sync.RWMutex
	entries map[string]pathEntry
	max     int
}

func newPathTable(max int) *pathTable {
	return &pathTable{entries: make(map[string]pathEntry), max: max}
}

// update records e for dest if it is fresher (newer origin timestamp) or a
// strictly shorter path than what we already hold. Returns true if stored.
func (pt *pathTable) update(dest string, e pathEntry) bool {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if cur, ok := pt.entries[dest]; ok {
		if e.OriginTS < cur.OriginTS {
			return false // stale announce; keep the newer path
		}
		if e.OriginTS == cur.OriginTS && e.Hops >= cur.Hops {
			// Same announce generation via an equal-or-longer path: just refresh.
			cur.LastSeen = e.LastSeen
			pt.entries[dest] = cur
			return false
		}
	}
	pt.entries[dest] = e
	if len(pt.entries) > pt.max {
		pt.evictOldestLocked()
	}
	return true
}

func (pt *pathTable) lookup(dest string) (pathEntry, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	e, ok := pt.entries[dest]
	return e, ok
}

func (pt *pathTable) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range pt.entries {
		if first || e.LastSeen.Before(oldest) {
			oldestKey, oldest, first = k, e.LastSeen, false
		}
	}
	if oldestKey != "" {
		delete(pt.entries, oldestKey)
	}
}

// dedupSet remembers recently-seen flood keys so a re-received announce is not
// re-forwarded. Entries older than the TTL are pruned opportunistically.
type dedupSet struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

func newDedupSet(ttl time.Duration) *dedupSet {
	return &dedupSet{seen: make(map[string]time.Time), ttl: ttl}
}

// observe reports whether key was already seen within the TTL; otherwise it
// records key and returns false.
func (d *dedupSet) observe(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if t, ok := d.seen[key]; ok && now.Sub(t) < d.ttl {
		return true
	}
	if len(d.seen) > 8192 {
		for k, t := range d.seen {
			if now.Sub(t) >= d.ttl {
				delete(d.seen, k)
			}
		}
	}
	d.seen[key] = now
	return false
}

// PathTo returns the next-hop address and hop count for a destination hash if an
// announce has established a path to it. Used by later phases (and path
// requests) to route toward destinations learned via flooding.
func (d *Discovery) PathTo(destHash string) (nextHop string, hops uint8, ok bool) {
	if d.paths == nil {
		return "", 0, false
	}
	e, found := d.paths.lookup(destHash)
	if !found {
		return "", 0, false
	}
	return e.NextHop, e.Hops, true
}

// announceSelf floods this node's identity + reachability across interfaces. It
// is the medium-agnostic evolution of broadcastDiscovery: a self-signed announce
// that transport nodes propagate, so the node becomes reachable without DNS or a
// bootstrap server.
func (d *Discovery) announceSelf() {
	if d.iface == nil {
		return
	}
	if ap := d.buildSelfAnnounce(); ap != nil {
		d.sendAnnounceDirect(ap)
	}
}

// buildSelfAnnounce assembles and signs a fresh announce for this node, or nil if
// identity is not yet set. It does not emit anything (so path-request responses
// can reuse it), and does not require an interface.
func (d *Discovery) buildSelfAnnounce() *protocol.AnnouncePayload {
	if len(d.signPriv) == 0 || d.selfID == "" {
		return nil
	}
	d.mu.RLock()
	ap := protocol.AnnouncePayload{
		DestHash:     d.selfID,
		PubKey:       d.pubKey,
		MLKEMPub:     d.mlkemPub,
		Port:         d.port,
		Capabilities: append([]string(nil), d.capabilities...),
		RelayIDs:     append([]string(nil), d.relayIDs...),
		Timestamp:    time.Now().UnixNano(),
		Nonce:        randUint64(),
		HopCount:     0,
	}
	d.mu.RUnlock()
	ap.Sign(d.signPriv)
	return &ap
}

// sendAnnounce wraps an announce payload in a signed packet and broadcasts it on
// the interface.
func (d *Discovery) sendAnnounce(ap *protocol.AnnouncePayload) { d.sendAnnounceMode(ap, false) }

// sendAnnounceDirect also delivers point-to-point, for announces that must reach a
// specific peer we cannot broadcast to (our own, and answers to a path request).
func (d *Discovery) sendAnnounceDirect(ap *protocol.AnnouncePayload) { d.sendAnnounceMode(ap, true) }

func (d *Discovery) sendAnnounceMode(ap *protocol.AnnouncePayload, direct bool) {
	if d.iface == nil {
		return
	}
	data, err := json.Marshal(ap)
	if err != nil {
		return
	}
	pkt := protocol.NewPacket(protocol.PacketTypeAnnounce, data, "ANY", "")
	pkt.SourceNode = d.selfID
	pkt.Sign(d.signPriv)
	if b, err := pkt.MarshalBinary(); err == nil {
		if direct {
			d.floodFrameDirect(b)
		} else {
			d.floodFrame(b)
		}
	}
}

// handleAnnounce verifies, learns, and (if this node is a transport) re-floods an
// incoming announce. It returns whether the announce was accepted as fresh (used
// in tests). remoteAddr is the peer we received it from — the recorded next hop.
func (d *Discovery) handleAnnounce(remoteAddr *net.UDPAddr, srcIface iface.Interface, pkt *protocol.Packet) bool {
	var ap protocol.AnnouncePayload
	if err := json.Unmarshal(pkt.Payload, &ap); err != nil {
		return false
	}
	// Ignore announces for ourselves (loops) and any that fail key-binding or
	// the announcer's own signature — the latter makes it impossible to forge an
	// announce for another node's identity.
	if ap.DestHash == d.selfID || !ap.VerifyBound() {
		return false
	}
	// The destination is reachable (next hop) over the interface we heard the
	// announce on, so route unicast toward it there.
	d.rememberIface(ap.DestHash, srcIface)
	// Suppress re-forwarding an announce we have already seen in this flood.
	if d.seenAnn.observe(ap.DestHash + ":" + u64hex(ap.Nonce)) {
		return false
	}

	// Learn the announced node, but only treat this as first-hand contact when the
	// announce came straight from its origin (HopCount 0). Then it is self-signed,
	// key-bound, and arrived from the origin's own address, so both liveness and
	// address are trustworthy — the same standing as a discovery packet.
	//
	// A re-flooded announce (HopCount > 0) is hearsay twice over: it is no evidence
	// the origin is still alive, and remoteAddr is the *forwarder's* address, not
	// the origin's — recording it would corrupt the origin's address with a
	// transport node's. Learn identity, keys and capabilities only; reachability
	// for such a node comes from the path table below, and liveness from a
	// first-hand probe. A later direct announce heals the address automatically.
	// RelayIDs, unlike the address, IS carried across forwarding: it is covered by
	// the announcer's own signature (VerifyBound above), so a re-forwarded copy is
	// still the announcer's own statement about itself, not the forwarder's claim.
	// This is what lets a NAT'd node's reservations propagate authentically — the
	// job peer-exchange gossip used to do unauthenticated.
	if ap.HopCount == 0 {
		d.updateNode(ap.DestHash, remoteAddr.String(), ap.PubKey, ap.SignKey, ap.Port, ap.Capabilities, ap.RelayIDs, ap.MLKEMPub)
	} else {
		d.learnCandidate(ap.DestHash, remoteAddr.String(), ap.PubKey, ap.SignKey, ap.Port, ap.Capabilities, ap.RelayIDs, ap.MLKEMPub)
	}
	annCopy := ap // cache a copy so a later path request can re-flood it
	stored := d.paths.update(ap.DestHash, pathEntry{
		Iface:    ifaceName(d.iface),
		NextHop:  remoteAddr.String(),
		Hops:     ap.HopCount,
		LastSeen: time.Now(),
		OriginTS: ap.Timestamp,
		Ann:      &annCopy,
	})

	// Forward (flood) only if this node is a transport (relay-capable) and the
	// announce has hops left. Re-sign the packet as this hop, bump HopCount, and
	// re-broadcast after a randomized spread delay.
	if stored && d.isTransport() && int(ap.HopCount)+1 <= announceHopMax {
		fwd := ap
		fwd.HopCount = ap.HopCount + 1
		go d.forwardAnnounce(&fwd)
	}
	return stored
}

// forwardAnnounce re-broadcasts an announce after a small randomized delay so a
// wave of transport nodes doesn't retransmit in lockstep.
func (d *Discovery) forwardAnnounce(ap *protocol.AnnouncePayload) {
	time.Sleep(randSpread(announceSpreadMax))
	select {
	case <-d.ctx.Done():
		return
	default:
	}
	d.sendAnnounce(ap)
}

// isTransport reports whether this node advertises the "relay" capability and so
// forwards announces for others.
func (d *Discovery) isTransport() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, c := range d.capabilities {
		if c == "relay" {
			return true
		}
	}
	return false
}

// requestHopMax bounds how far a path request floods.
const requestHopMax = 128

// RequestPath floods a path request for destHash, so any transport holding a
// path (or the destination itself) re-floods that destination's announce back,
// establishing a route without DNS or a bootstrap server.
func (d *Discovery) RequestPath(destHash string) {
	d.sendPathRequest(&protocol.PathRequestPayload{
		DestHash: destHash,
		Nonce:    randUint64(),
		HopCount: 0,
	})
}

// ResolvePath returns true if a path to destHash is (or becomes) known: it
// short-circuits when a path already exists, otherwise floods a path request and
// waits up to timeout for one to arrive. This is the medium-agnostic analogue of
// a DHT FindNode — "have their ID" -> "can reach them".
func (d *Discovery) ResolvePath(destHash string, timeout time.Duration) bool {
	if _, _, ok := d.PathTo(destHash); ok {
		return true
	}
	d.RequestPath(destHash)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if d.ctx != nil {
			select {
			case <-d.ctx.Done():
				return false
			default:
			}
		}
		time.Sleep(50 * time.Millisecond)
		if _, _, ok := d.PathTo(destHash); ok {
			return true
		}
	}
	_, _, ok := d.PathTo(destHash)
	return ok
}

// sendPathRequest wraps a path request in a signed packet and broadcasts it.
func (d *Discovery) sendPathRequest(pr *protocol.PathRequestPayload) {
	if d.iface == nil || len(d.signPriv) == 0 {
		return
	}
	data, err := json.Marshal(pr)
	if err != nil {
		return
	}
	pkt := protocol.NewPacket(protocol.PacketTypePathRequest, data, "ANY", "")
	pkt.SourceNode = d.selfID
	pkt.Sign(d.signPriv)
	if b, err := pkt.MarshalBinary(); err == nil {
		// A path request is only useful if it reaches a node that holds the path.
		// Broadcast reaches the local link; the relays that actually know where a
		// NAT'd destination lives are reachable only point-to-point.
		d.floodFrameDirect(b)
	}
}

// handlePathRequest answers or forwards a path request. If this node can answer
// (it is the destination, or holds a cached announce for it) it (re)floods the
// corresponding announce and returns it; otherwise, if it is a transport with
// hops left, it forwards the request. The returned announce and forwarded bool
// are used in tests. Emission is a no-op without an interface.
func (d *Discovery) handlePathRequest(pkt *protocol.Packet) (*protocol.AnnouncePayload, bool) {
	var pr protocol.PathRequestPayload
	if err := json.Unmarshal(pkt.Payload, &pr); err != nil || pr.DestHash == "" {
		return nil, false
	}
	// Dedup the request flood so it does not loop.
	if d.seenAnn.observe("REQ:" + pr.DestHash + ":" + u64hex(pr.Nonce)) {
		return nil, false
	}

	// We are the destination: answer with a fresh self-announce.
	if pr.DestHash == d.selfID {
		ap := d.buildSelfAnnounce()
		if ap != nil {
			d.sendAnnounceDirect(ap)
		}
		return ap, false
	}

	// We hold a cached announce for the destination: re-flood it toward the
	// requester (one hop further than we are from the destination).
	if e, ok := d.paths.lookup(pr.DestHash); ok && e.Ann != nil {
		resp := *e.Ann
		resp.HopCount = e.Hops + 1
		d.sendAnnounceDirect(&resp)
		return &resp, false
	}

	// Otherwise, transports flood the request one hop further.
	if d.isTransport() && int(pr.HopCount)+1 <= requestHopMax {
		fwd := pr
		fwd.HopCount = pr.HopCount + 1
		d.sendPathRequest(&fwd)
		return nil, true
	}
	return nil, false
}

func ifaceName(i iface.Interface) string {
	if i == nil {
		return ""
	}
	return i.Name()
}

// sourcedFrame is an inbound frame tagged with the interface it arrived on, so
// the read loop can learn which interface reaches a given node.
type sourcedFrame struct {
	iface iface.Interface
	frame iface.InboundFrame
}

// floodFrame broadcasts a frame across every interface, so announces, path
// requests, and discovery cross bridges (e.g. a TCP client to another subnet),
// not just the local UDP broadcast domain.
// announceFanout bounds how many known peers an announce is unicast to, so
// flooding stays proportional on a large table. Loops and duplicates are absorbed
// by the (DestHash, Nonce) dedup set in handleAnnounce.
const announceFanout = 12

func (d *Discovery) floodFrame(b []byte) {
	for _, i := range d.ifaces {
		i.Send(iface.Broadcast, b)
	}
}

// floodFrameDirect broadcasts and additionally sends point-to-point to a bounded
// set of verified peers.
//
// Broadcast alone only ever reaches one link, so across the internet — and to any
// NAT'd peer, which by definition shares no reachable broadcast domain with us — an
// announce arrives only if it is also sent point-to-point. Without that, a node's
// signed announce never leaves its own LAN, and the reservation relays a NAT'd node
// advertises cannot reach the relays that must route to it.
//
// This is used ONLY for a node's own announce, never for re-forwarding someone
// else's. Unicasting forwarded announces too would multiply each announce by the
// fanout at every transport hop; the originator doing it once is enough to seed the
// relays it can actually reach, and they redistribute by their existing means.
func (d *Discovery) floodFrameDirect(b []byte) {
	d.floodFrame(b)

	d.mu.RLock()
	targets := make([]struct{ id, addr string }, 0, announceFanout)
	for _, n := range d.nodes {
		if len(targets) >= announceFanout {
			break
		}
		if n.Active && n.Address != "" {
			targets = append(targets, struct{ id, addr string }{n.ID, n.Address})
		}
	}
	d.mu.RUnlock()

	for _, t := range targets {
		d.ifaceFor(t.id).Send(t.addr, b)
	}
}

// rememberIface records that nodeID is reachable over interface i (where we last
// heard from or about it).
func (d *Discovery) rememberIface(nodeID string, i iface.Interface) {
	if nodeID == "" || i == nil || d.nodeIface == nil {
		return
	}
	d.mu.Lock()
	d.nodeIface[nodeID] = i
	d.mu.Unlock()
}

// ifaceFor returns the interface to reach nodeID, falling back to the primary UDP
// interface when it was never heard on a specific one.
func (d *Discovery) ifaceFor(nodeID string) iface.Interface {
	if d.nodeIface != nil {
		d.mu.RLock()
		i := d.nodeIface[nodeID]
		d.mu.RUnlock()
		if i != nil {
			return i
		}
	}
	return d.iface
}

// Links returns the encrypted-session manager for establishing Reticulum-style
// Links to peers over the interfaces, or nil if no signing key was set before
// Start.
func (d *Discovery) Links() *link.Manager { return d.linkMgr }

// DialNode establishes an encrypted Link to a known node by ID, using the
// address and Ed25519 key learned via discovery. The link rides whichever
// interface reaches the node (UDP or a bridge).
func (d *Discovery) DialNode(nodeID string, timeout time.Duration) (*link.Link, error) {
	if d.linkMgr == nil {
		return nil, fmt.Errorf("links not enabled (no signing key)")
	}
	d.mu.RLock()
	node := d.nodes[nodeID]
	d.mu.RUnlock()
	if node == nil {
		return nil, fmt.Errorf("node %s is not known", nodeID)
	}
	if len(node.SignKey) != ed25519.PublicKeySize || node.Address == "" {
		return nil, fmt.Errorf("node %s missing address or signing key", nodeID)
	}
	return d.linkMgr.DialCached(node.Address, ed25519.PublicKey(node.SignKey), timeout)
}

// linkSend routes a link frame to addr over the interface that address was last
// heard on (a bridge if that is where the peer is), falling back to the primary
// UDP interface — so a link can be dialed to a directly-addressable peer even
// before any frame has been received from it.
func (d *Discovery) linkSend(addr string, frame []byte) error {
	d.mu.RLock()
	i := d.addrIface[addr]
	d.mu.RUnlock()
	if i == nil {
		i = d.iface
	}
	return i.Send(addr, frame)
}

// mtuFor reports the transport MTU for a peer address — the advertised MTU of
// the interface that address was last heard on (a small datagram/radio MTU or a
// large TCP-bridge one), or the primary interface's when unknown. Links use it to
// size message chunks so a datagram frame stays within one packet.
func (d *Discovery) mtuFor(addr string) int {
	d.mu.RLock()
	i := d.addrIface[addr]
	d.mu.RUnlock()
	if i == nil {
		i = d.iface
	}
	if i == nil {
		return 0 // unknown -> link falls back to its default chunk size
	}
	return i.Caps().MTU
}

// rememberAddrIface records the interface a peer address was last heard on.
func (d *Discovery) rememberAddrIface(addr string, i iface.Interface) {
	if addr == "" || i == nil || d.addrIface == nil {
		return
	}
	d.mu.Lock()
	d.addrIface[addr] = i
	d.mu.Unlock()
}

// fanIn copies one interface's inbound frames into the merged channel the read
// loop drains, exiting when the interface closes or the node stops.
func (d *Discovery) fanIn(i iface.Interface) {
	for {
		select {
		case <-d.ctx.Done():
			return
		case f, ok := <-i.Frames():
			if !ok {
				return
			}
			d.markIfaceActive(i.Name()) // a frame means this interface (bridge) is live
			select {
			case d.inbound <- sourcedFrame{iface: i, frame: f}:
			case <-d.ctx.Done():
				return
			}
		}
	}
}

// bridgeLivenessTimeout is how long a bridge may carry no traffic after being
// added before it is reported as likely misconfigured/filtered. A working bridge
// exchanges announces within a discovery cycle, well under this.
const bridgeLivenessTimeout = 45 * time.Second

// bridgeStat tracks whether a bridge interface has ever carried a frame, so a
// silently-dead bridge can be reported once.
type bridgeStat struct {
	addr    string
	created time.Time
	active  atomic.Bool
	warned  bool
}

// registerBridge starts liveness tracking for a bridge interface.
func (d *Discovery) registerBridge(name, addr string) {
	if d.bridges == nil {
		return
	}
	d.mu.Lock()
	d.bridges[name] = &bridgeStat{addr: addr, created: time.Now()}
	d.mu.Unlock()
}

// markIfaceActive records that an interface carried a frame (used for bridge
// liveness; a no-op for interfaces that aren't tracked bridges).
func (d *Discovery) markIfaceActive(name string) {
	if d.bridges == nil {
		return
	}
	d.mu.RLock()
	bs := d.bridges[name]
	d.mu.RUnlock()
	if bs != nil {
		bs.active.Store(true)
	}
}

// checkBridgeLiveness warns once for any bridge that has carried no traffic within
// bridgeLivenessTimeout of being added — the "bridges: 1, peers: 0" case, which is
// otherwise indistinguishable from a firewalled/misconfigured far side.
func (d *Discovery) checkBridgeLiveness() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for name, bs := range d.bridges {
		if bs.warned || bs.active.Load() {
			continue
		}
		if now.Sub(bs.created) > bridgeLivenessTimeout {
			bs.warned = true
			log.Printf("discovery: bridge %q (%s) connected but received no traffic in %s — the far side is likely not running a bridge listener on that port, is filtered, or requires a bridge pre-shared key this node does not have", name, bs.addr, bridgeLivenessTimeout)
		}
	}
}

// AddBridge dials a transport node over TCP and adds it as an interface, so this
// node's announces/path-requests reach — and remote ones arrive from — a network
// the local broadcast domain cannot. Call before Start. This is how discovery
// crosses subnets/the internet without DNS: point a bridge at one reachable node.
// A bridge PSK, when set via SetBridgePSK, gates who may attach in either
// direction; without one the bridge is open, which is what a public seed wants.
func (d *Discovery) AddBridge(name, remoteAddr string) error {
	tc, err := iface.NewTCPClientInterfaceAuth(name, remoteAddr, d.bridgePSK())
	if err != nil {
		return err
	}
	d.ifaces = append(d.ifaces, tc)
	d.registerBridge(name, remoteAddr)
	return nil
}

// AddListenBridge starts a TCP server interface that accepts inbound bridges, so
// other nodes can AddBridge to this one. A transport node with a reachable
// address runs this to become a bridge point. Returns the actual bound address
// (useful when listenAddr uses port 0). Call before Start.
func (d *Discovery) AddListenBridge(name, listenAddr string) (string, error) {
	ts, err := iface.NewTCPServerInterfaceAuth(name, listenAddr, d.bridgePSK())
	if err != nil {
		return "", err
	}
	d.ifaces = append(d.ifaces, ts)
	d.registerBridge(name, ts.Addr().String())
	return ts.Addr().String(), nil
}

// AddAutoInterface joins the zero-config LAN multicast group so this node
// discovers — and is discovered by — other SyncSwarm nodes on the same physical
// network, with no bootstrap host or DNS seed. Call before Start. Returns
// iface.ErrNoMulticast when the host has no multicast-capable interface (a
// loopback-only container), which a caller should treat as "no LAN peering here"
// rather than a fatal error.
func (d *Discovery) AddAutoInterface(name string) error {
	ai, err := iface.NewAutoInterface(name)
	if err != nil {
		return err
	}
	d.ifaces = append(d.ifaces, ai)
	return nil
}

// AddLoRaInterface opens a serial-attached LoRa modem (RNode / Meshtastic /
// MeshCore in KISS mode) at device and joins the mesh over the air — announces
// and path requests flood over it like any broadcast medium. Call before Start.
// baud 0 uses a sensible default. Returns an error if the device can't be opened
// (or the platform has no serial backend).
// dutyCycle limits transmissions to that fraction of wall time on air (e.g. 0.01
// for the 1% common in licence-free sub-GHz bands); 0 disables the limit.
func (d *Discovery) AddLoRaInterface(name, device string, baud int, dutyCycle float64) error {
	li, err := iface.NewLoRaInterface(name, device, baud)
	if err != nil {
		return err
	}
	li.SetDutyCycle(dutyCycle, 0)
	d.ifaces = append(d.ifaces, li)
	return nil
}

// AddSerialInterface opens a KISS/serial radio modem (TNC, packet radio) at
// device and joins the mesh over it. Call before Start. baud 0 uses a default.
func (d *Discovery) AddSerialInterface(name, device string, baud int, dutyCycle float64) error {
	si, err := iface.NewSerialInterface(name, device, baud)
	if err != nil {
		return err
	}
	si.SetDutyCycle(dutyCycle, 0)
	d.ifaces = append(d.ifaces, si)
	return nil
}

// --- small helpers ---------------------------------------------------------

func randUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(b[:])
}

// randSpread returns a random duration in [0, max).
func randSpread(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return max / 2
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(max))
}

func u64hex(n uint64) string {
	const digits = "0123456789abcdef"
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = digits[n&0xf]
		n >>= 4
	}
	return string(buf[:])
}
