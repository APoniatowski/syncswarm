package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/APoniatowski/syncswarm/internal/dht"
	"github.com/APoniatowski/syncswarm/internal/iface"
	"github.com/APoniatowski/syncswarm/internal/link"
	"github.com/APoniatowski/syncswarm/internal/protocol"
)

const (
	discoveryPort         = 64512           // Same as defined in update package
	maxLatency            = time.Second * 2 // Maximum acceptable latency
	minNodes              = 2               // Minimum number of nodes before increasing discovery interval
	baseDiscoveryInterval = time.Minute * 1
	maxDiscoveryInterval  = time.Minute * 30
	latencyCheckInterval  = time.Second * 30
	gossipInterval        = time.Second * 30 // Peer-exchange gossip cadence
	maxGossipPeers        = 8                // Upper bound on gossip fan-out per tick

	// Anti-eclipse limits (Round 9): bound the peer table and its diversity so a
	// Sybil flood cannot evict honest peers or fill the table.
	maxPeers          = 512 // total peer-table cap
	maxPeersPerSubnet = 8   // cap on non-bootstrap peers sharing an IP /24 (or /48)
	maxGossipAccept   = 32  // peers merged from a single gossip message

	// maxVerifyPerRound bounds how many gossip-discovered (unverified) peers are
	// probed per latency round. Each probe can cost up to maxLatency, so an
	// unbounded sweep of a full table would stall the maintenance loop.
	maxVerifyPerRound = 8

	// latencyProbeConcurrency bounds how many latency checks run at once. Probes
	// are mostly idle waiting on a reply, so a modest pool turns a round that
	// scaled with the table (2s per unreachable peer, sequentially) into one that
	// scales with table/concurrency — while staying a small enough burst not to
	// look like a scan or overwhelm a low-powered peer.
	latencyProbeConcurrency = 16
)

// Node represents a discovered peer in the network
type Node struct {
	ID           string
	Address      string
	LastSeen     time.Time
	Latency      time.Duration
	Active       bool
	PubKey       []byte   // X25519 public key advertised by the peer
	SignKey      []byte   // Ed25519 public key; ID == protocol.DeriveNodeID(SignKey)
	Port         uint16   // Transfer/data port advertised by the peer
	Capabilities []string // Advertised capabilities, e.g. ["relay"]
	RelayIDs     []string // NodeIDs of relays this peer is reachable through (circuit reservations)
	MLKEMPub     []byte   // Optional ML-KEM-768 public key for post-quantum hybrid sealing
}

// Discovery manages peer discovery and maintenance
type Discovery struct {
	mu     sync.RWMutex
	nodes  map[string]*Node
	selfID string
	iface  iface.Interface // primary datagram transport (UDP); used for unicast replies

	// ifaces is every transport this node speaks over: the primary UDP interface
	// plus any bridges (e.g. a TCP client to a transport node on another subnet).
	// Broadcasts (announces, path requests, discovery) fan out across all of them,
	// and inbound frames from all of them are merged into `inbound`, so a bridge
	// carries discovery across networks the local broadcast domain cannot reach.
	ifaces  []iface.Interface
	inbound chan sourcedFrame

	// nodeIface records which interface each node was last heard on, so unicast
	// (latency, gossip, findnode) routes to a bridged peer over its bridge rather
	// than the local UDP interface. Unknown nodes fall back to the primary UDP
	// interface, so non-bridged behavior is unchanged. Guarded by mu.
	nodeIface map[string]iface.Interface
	// addrIface records the interface each peer address was last heard on, so
	// Link frames (addressed by address, not node ID) route back over the right
	// interface. Guarded by mu.
	addrIface map[string]iface.Interface
	// linkMgr establishes Reticulum-style encrypted sessions over the interfaces
	// (created in Start when a signing key is set). Nil until then.
	linkMgr *link.Manager

	// bridges tracks each bridge interface's liveness so a bridge that connects
	// but never carries traffic (silently misconfigured/filtered) is reported,
	// instead of sitting at "bridges: 1, peers: 0". Keyed by interface name.
	bridges map[string]*bridgeStat

	// Reticulum-style announce discovery: a path table built from flooded
	// announces, plus a dedup set to suppress re-forwarding the same announce.
	paths   *pathTable
	seenAnn *dedupSet
	ctx     context.Context
	cancel  context.CancelFunc

	// Per-hop transport routing (P3): a dedup set bounding routed-packet loops and
	// a handler invoked when a routed packet reaches this node as its destination.
	routedSeen *dedupSet
	onRouted   atomic.Pointer[func(inner []byte, origin string)]

	nonceCounter atomic.Uint64

	pendingMu sync.Mutex
	pending   map[uint64]pendingLatency

	// Kademlia routing table for structured NodeID -> address lookup (10.4). Nil
	// when selfID is not a valid DHT key (e.g. in unit tests using symbolic IDs),
	// in which case FindNode degrades to a local-table lookup. lookups correlates
	// outstanding FIND_NODE replies by nonce.
	rt       *dht.RoutingTable
	lookupMu sync.Mutex
	lookups  map[uint64]chan []protocol.DHTContact

	// AutoNAT reachability detection (opt-in via EnableReachabilityChecks). The
	// node periodically asks peers to dial its data port back and concludes
	// whether it is reachable; onReachability fires when that flips. reachPending
	// correlates dial-back results by nonce.
	reachMu        sync.Mutex
	reachEnabled   bool
	reachKnown     bool
	reachable      bool
	onReachability func(bool)
	reachPending   map[uint64]chan bool
	// soloFailures counts consecutive rounds in which the only responder reported
	// the data port unreachable (see reachSoloRounds).
	soloFailures int

	// Local advertised identity (set via SetIdentity; zero values until then).
	pubKey       []byte
	mlkemPub     []byte // optional ML-KEM-768 public key (SetMLKEMKey)
	port         uint16
	capabilities []string
	relayIDs     []string // relays we hold circuit reservations with (advertised)
	bridgePSKVal []byte   // optional PSK gating who may attach a TCP bridge

	// observedCounts tallies the external addresses peers report seeing us at,
	// so we can learn our own public (reflexive) address behind NAT.
	observedMu     sync.Mutex
	observedCounts map[string]int

	// signPriv signs this node's outgoing packets; signPub is advertised so
	// peers can bind this node's ID to its key. Set via SetSigningKey.
	signPriv ed25519.PrivateKey
	signPub  ed25519.PublicKey

	// Bootstrap peer addresses (host:port UDP) set via SetBootstrapPeers.
	bootstrapPeers []string

	// peerCachePath, if set, persists recently-seen peer addresses so a node
	// re-bootstraps from them across restarts (reducing dependence on the seed).
	peerCachePath string
	// bootstrapWarned tracks whether we've already logged that no bootstrap/seed
	// address resolved, so the warning fires once per outage, not every tick.
	bootstrapWarned atomic.Bool

	// listenPort is the actual UDP port this instance is bound to (resolved from
	// the requested port, which may have been 0 for an ephemeral port).
	listenPort int

	// Churn counters (observability): cumulative peers admitted and evicted/
	// expired over this node's lifetime. Guarded by mu.
	joins     uint64
	evictions uint64
}

// pendingLatency is one outstanding latency check: the channel awaiting the
// reply, plus the node ID we addressed the check to.
//
// The node ID matters for correctness, not bookkeeping. Liveness must prove that
// *that identity* is still there, not merely that something answers at its
// address. Without the binding, a node whose identity changed (storage wiped,
// host re-provisioned) leaves a ghost entry that its own successor keeps marking
// active by replying at the same address — and because path selection seals onion
// layers to the ghost's advertised public key, traffic routed through it is
// silently undeliverable.
type pendingLatency struct {
	nodeID string
	ch     chan time.Time
}

// PeerHealth is a point-in-time view of the peer table's composition and churn,
// for operational monitoring.
type PeerHealth struct {
	Total     int            // peers in the table
	Active    int            // peers currently reachable (passing latency checks)
	Inactive  int            // peers present but not currently reachable
	Subnets   int            // distinct /24 (or /48) groups represented
	PerSubnet map[string]int // subnet key -> peer count
	Joins     uint64         // cumulative peers admitted
	Evictions uint64         // cumulative peers evicted or expired
}

// PeerHealth returns the current peer-table composition and lifetime churn.
func (d *Discovery) PeerHealth() PeerHealth {
	d.mu.RLock()
	defer d.mu.RUnlock()

	h := PeerHealth{
		PerSubnet: make(map[string]int),
		Joins:     d.joins,
		Evictions: d.evictions,
	}
	for _, n := range d.nodes {
		h.Total++
		if n.Active {
			h.Active++
		} else {
			h.Inactive++
		}
		h.PerSubnet[subnetKey(n.Address)]++
	}
	h.Subnets = len(h.PerSubnet)
	return h
}

// NewDiscovery creates a new discovery service bound to listenPort. A listenPort
// of 0 requests an ephemeral port (useful for tests and multiple nodes per host);
// use Port() to read the actual bound port.
func NewDiscovery(selfID string, listenPort int) (*Discovery, error) {
	// Bind a broadcast-capable UDP datagram interface. It advertises a
	// fragmentation-safe sizing MTU (so payload-sizing layers like Links keep
	// datagrams within one IP packet), while the hard send cap stays at the UDP
	// payload max so large legacy gossip (peer-exchange) is still accepted.
	udp, err := iface.NewUDPInterfaceSized(
		"udp0",
		fmt.Sprintf(":%d", listenPort),
		fmt.Sprintf("255.255.255.255:%d", discoveryPort),
		iface.SafeDatagramMTU, // advertised: avoid IP fragmentation
		65507,                 // hard cap: UDP payload max (legacy gossip)
	)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	d := &Discovery{
		nodes:          make(map[string]*Node),
		selfID:         selfID,
		iface:          udp,
		ifaces:         []iface.Interface{udp},
		inbound:        make(chan sourcedFrame, 256),
		nodeIface:      make(map[string]iface.Interface),
		ctx:            ctx,
		cancel:         cancel,
		pending:        make(map[uint64]pendingLatency),
		observedCounts: make(map[string]int),
		listenPort:     udp.LocalAddr().(*net.UDPAddr).Port,
		lookups:        make(map[uint64]chan []protocol.DHTContact),
		reachPending:   make(map[uint64]chan bool),
		paths:          newPathTable(maxPaths),
		seenAnn:        newDedupSet(announceDedupTTL),
		routedSeen:     newDedupSet(announceDedupTTL),
		addrIface:      make(map[string]iface.Interface),
		bridges:        make(map[string]*bridgeStat),
	}
	// Enable the Kademlia routing table only when selfID is a valid DHT key.
	if id, err := dht.ParseID(selfID); err == nil {
		d.rt = dht.NewRoutingTable(id, dht.DefaultK)
	}

	return d, nil
}

// SetBridgePSK sets the pre-shared key required to attach a TCP bridge, in either
// direction. Empty (the default) leaves bridges open. Call before adding bridges;
// it does not re-authenticate ones already attached.
//
// This is access control, not confidentiality: discovery packets are already
// signed and payloads sealed end to end. What it decides is *who may attach at
// all* — a bridge host sees the discovery metadata of everyone bridged through it
// and can selectively drop traffic, so a private deployment should not accept
// arbitrary peers (SECURITY_AUDIT.md finding 3).
func (d *Discovery) SetBridgePSK(psk []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bridgePSKVal = append([]byte(nil), psk...)
}

func (d *Discovery) bridgePSK() []byte {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.bridgePSKVal
}

// SetRelayIDs advertises the relays this node holds circuit reservations with,
// so peers can route to it through one of them when it is not directly reachable.
func (d *Discovery) SetRelayIDs(ids []string) {
	d.mu.Lock()
	changed := len(ids) != len(d.relayIDs)
	if !changed {
		for i := range ids {
			if ids[i] != d.relayIDs[i] {
				changed = true
				break
			}
		}
	}
	d.relayIDs = append([]string(nil), ids...)
	d.mu.Unlock()

	// Reservations now propagate in the signed announce rather than in gossip, so
	// gaining or losing one has to re-announce: otherwise a NAT'd node stays
	// unreachable until the next periodic flood, and a dropped reservation keeps
	// drawing traffic to a relay that no longer holds it. Emitted outside the lock
	// — buildSelfAnnounce takes the read lock.
	if changed {
		d.announceSelf()
	}
}

// SetRelay toggles this node's advertised "relay" capability at runtime and
// re-advertises (discovery broadcast + announce) so peers learn of the change.
// This lets a node start relaying once it concludes it is reachable and stop if
// that changes, without a restart. isTransport() (announce forwarding) follows the
// same capability, so it flips too.
func (d *Discovery) SetRelay(on bool) {
	d.mu.Lock()
	caps := make([]string, 0, len(d.capabilities)+1)
	for _, c := range d.capabilities {
		if c != "relay" {
			caps = append(caps, c)
		}
	}
	if on {
		caps = append(caps, "relay")
	}
	d.capabilities = caps
	d.mu.Unlock()
	// Propagate the change immediately.
	d.broadcastDiscovery()
	d.announceSelf()
}

// recordObserved tallies an external address a peer reported seeing us at.
func (d *Discovery) recordObserved(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return
	}
	d.observedMu.Lock()
	d.observedCounts[host]++
	d.observedMu.Unlock()
}

// subnetKey returns a coarse network grouping (IPv4 /24 or IPv6 /48) for an
// address, used to bound how many peers from one operator enter the table.
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
		return "v4:" + strconv.Itoa(int(v4[0])) + "." + strconv.Itoa(int(v4[1])) + "." + strconv.Itoa(int(v4[2]))
	}
	return "v6:" + ip.Mask(net.CIDRMask(48, 128)).String()
}

// isBootstrapAddr reports whether addr shares a host with a configured bootstrap
// peer. Bootstrap peers are trust anchors: never counted for eviction or capped,
// so a node cannot be eclipsed away from them. Caller holds d.mu.
func (d *Discovery) isBootstrapAddr(addr string) bool {
	h1, _, err := net.SplitHostPort(addr)
	if err != nil {
		h1 = addr
	}
	for _, b := range d.bootstrapPeers {
		h2, _, err := net.SplitHostPort(b)
		if err != nil {
			h2 = b
		}
		if h1 == h2 {
			return true
		}
	}
	return false
}

// admitLocked enforces the anti-eclipse caps before a new peer at addr is added,
// evicting the stalest non-bootstrap peer from an over-full subnet or table.
// Returns false if no room can be made. Caller holds d.mu.
func (d *Discovery) admitLocked(addr string) bool {
	if d.isBootstrapAddr(addr) {
		return true // trust anchors are always admitted
	}
	sk := subnetKey(addr)
	subnetCount := 0
	var stalestSubnet, stalestGlobal *Node
	for _, n := range d.nodes {
		if d.isBootstrapAddr(n.Address) {
			continue // never evict trust anchors
		}
		if stalestGlobal == nil || n.LastSeen.Before(stalestGlobal.LastSeen) {
			stalestGlobal = n
		}
		if subnetKey(n.Address) == sk {
			subnetCount++
			if stalestSubnet == nil || n.LastSeen.Before(stalestSubnet.LastSeen) {
				stalestSubnet = n
			}
		}
	}
	if subnetCount >= maxPeersPerSubnet {
		if stalestSubnet == nil {
			return false
		}
		delete(d.nodes, stalestSubnet.ID)
		d.evictions++
	}
	if len(d.nodes) >= maxPeers {
		if stalestGlobal == nil {
			return false
		}
		delete(d.nodes, stalestGlobal.ID)
		d.evictions++
	}
	return true
}

// ExternalHost returns the public host most peers report seeing this node at, or
// "" if no observations yet. Used to advertise a reachable address behind NAT.
func (d *Discovery) ExternalHost() string {
	d.observedMu.Lock()
	defer d.observedMu.Unlock()
	best, bestN := "", 0
	for host, n := range d.observedCounts {
		if n > bestN {
			best, bestN = host, n
		}
	}
	return best
}

// Port returns the actual UDP port this discovery instance is listening on.
func (d *Discovery) Port() int {
	return d.listenPort
}

// SetIdentity stores the local node's advertised routing/identity information.
// These values are populated into outgoing discovery and peer-exchange packets.
// It is safe to leave unset: fields default to their zero values.
func (d *Discovery) SetIdentity(pubKey []byte, port uint16, capabilities []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pubKey = pubKey
	d.port = port
	d.capabilities = capabilities
}

// SetMLKEMKey advertises this node's optional ML-KEM-768 public key, so peers can
// seal traffic to it with post-quantum hybrid encryption. Call before Start.
func (d *Discovery) SetMLKEMKey(pub []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mlkemPub = pub
}

// SetSigningKey installs the Ed25519 identity key used to sign this node's
// outgoing packets. The corresponding public key is advertised so peers can
// verify packets and bind this node's ID to the key.
func (d *Discovery) SetSigningKey(priv ed25519.PrivateKey) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signPriv = priv
	if len(priv) == ed25519.PrivateKeySize {
		d.signPub = priv.Public().(ed25519.PublicKey)
	}
}

// SetBootstrapPeers stores a list of bootstrap peer addresses (host:port UDP)
// that are unicast a discovery packet on Start and on every discovery tick.
func (d *Discovery) SetBootstrapPeers(addrs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bootstrapPeers = append([]string(nil), addrs...)
}

// Start begins the discovery process
func (d *Discovery) Start() {
	// Enable encrypted Link sessions over the interfaces once a signing key is
	// available (needed to sign link proofs). Created before the read loop so it
	// can receive inbound link frames.
	if len(d.signPriv) == ed25519.PrivateKeySize && d.linkMgr == nil {
		d.linkMgr = link.NewManager(d.signPriv, d.linkSend)
		// Size link message chunks to the transport a peer is reached over, so
		// datagram/radio links don't emit IP-fragmenting frames.
		d.linkMgr.SetMTUFunc(d.mtuFor)
	}

	// Fan every interface's inbound frames into the merged channel the read loop
	// drains, so frames from the UDP interface and any bridge are handled alike.
	for _, i := range d.ifaces {
		go d.fanIn(i)
	}
	go d.listenForPeers()
	go d.maintainPeers()

	// Reach out to configured bootstrap peers immediately so a fresh node can
	// join the swarm without waiting for the first broadcast tick.
	d.sendBootstrapDiscovery()
	d.announceSelf() // announce ourselves right away too

	// When AutoNAT is on, run an initial reachability check soon after peers are
	// discovered rather than waiting a full re-check interval.
	d.reachMu.Lock()
	enabled := d.reachEnabled
	d.reachMu.Unlock()
	if enabled {
		go d.initialReachabilityCheck()
	}
}

// initialReachabilityCheck retries a dial-back round every few seconds until a
// determination is reached (enough peers must be known first), then stops and
// leaves periodic re-checks to maintainPeers.
func (d *Discovery) initialReachabilityCheck() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.checkReachability()
			if _, known := d.Reachable(); known {
				return
			}
		}
	}
}

// Stop halts all discovery activities
func (d *Discovery) Stop() {
	d.savePeerCache() // flush known peers so the next start re-bootstraps from them
	d.cancel()
	for _, i := range d.ifaces {
		i.Close()
	}
}

// Bootstrap re-sends a discovery packet to all configured bootstrap peers. It is
// safe to call repeatedly and is useful for (re)joining a swarm on demand rather
// than waiting for the next discovery tick.
func (d *Discovery) Bootstrap() {
	d.sendBootstrapDiscovery()
}

// listenForPeers handles incoming discovery packets
func (d *Discovery) listenForPeers() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case sf, ok := <-d.inbound:
			if !ok {
				return // all interfaces closed
			}
			frame := sf.frame
			srcIface := sf.iface
			// Re-resolve the medium-specific source address back to a *net.UDPAddr
			// so every downstream handler keeps its existing signature.
			remoteAddr, err := net.ResolveUDPAddr("udp", frame.Addr)
			if err != nil {
				continue
			}

			var packet protocol.Packet
			if err := packet.UnmarshalBinary(frame.Data); err != nil {
				continue
			}

			// Remember which interface reaches this source address (Link frames are
			// addressed by address, not node ID).
			d.rememberAddrIface(frame.Addr, srcIface)

			// Link frames are self-authenticating (the proof is signed inside the
			// payload; data is AEAD-sealed) and deliberately carry no packet-level
			// signature, so the initiator stays anonymous. Dispatch them before the
			// signature gate that drops unsigned packets.
			switch packet.Type {
			case protocol.PacketTypeLinkRequest, protocol.PacketTypeLinkProof, protocol.PacketTypeLinkData:
				if d.linkMgr != nil {
					d.linkMgr.Deliver(remoteAddr.String(), &packet)
				}
				continue
			case protocol.PacketTypeRoutedDiscovery:
				// Same per-hop forwarding as PacketTypeRouted, but the inner bytes
				// are a signed discovery packet destined for this node's own
				// discovery processing rather than the application handler.
				d.handleRoutedDiscovery(&packet, remoteAddr, srcIface)
				continue
			case protocol.PacketTypeRouted:
				// Per-hop transport routing: forwarded before the signature gate
				// because forwarding mutates the hop limit and the payload is
				// self-authenticating (sealed end to end). Dedup + hop limit bound it.
				d.handleRouted(&packet)
				continue
			}

			// Drop packets that fail integrity verification
			if !packet.Verify() {
				continue
			}

			// Remember which interface reaches the sender, so unicast replies and
			// later traffic to it route over the same interface (e.g. a bridge).
			d.rememberIface(packet.SignerID(), srcIface)

			// Peer-exchange packets carry a different payload shape, so handle
			// them before attempting to decode a DiscoveryPayload.
			if packet.Type == protocol.PacketTypePeerExchange {
				var px protocol.PeerExchangePayload
				if err := json.Unmarshal(packet.Payload, &px); err != nil {
					continue
				}
				// Cap peers accepted from one gossip message so a single sender
				// cannot flood the table.
				// A gossip payload is signed by its sender, so the entry describing
				// the *sender itself* is a first-party statement — the same binding
				// the direct discovery path requires. Entries about anyone else are
				// third-party claims. Only the former may assert capabilities and
				// reservation relays.
				gossiper := packet.SignerID()
				selfAttested := gossiper != "" && packet.SourceNode == gossiper
				for i, pi := range px.Peers {
					if i >= maxGossipAccept {
						break
					}
					d.mergePeer(pi, selfAttested && pi.NodeID == gossiper)
				}
				continue
			}

			// Kademlia FIND_NODE query: bind the requester to its key, learn it,
			// and reply with our closest known contacts to the target.
			if packet.Type == protocol.PacketTypeFindNode {
				var fn protocol.FindNodePayload
				if err := json.Unmarshal(packet.Payload, &fn); err != nil {
					continue
				}
				signerID := packet.SignerID()
				if fn.NodeID != signerID || packet.SourceNode != signerID {
					continue
				}
				d.updateNode(fn.NodeID, remoteAddr.String(), fn.PubKey, packet.SignerKey, fn.Port, nil, nil, nil)
				d.handleFindNode(remoteAddr, fn)
				continue
			}

			// Kademlia FIND_NODE reply: learn the returned contacts and hand them
			// to the waiting lookup.
			if packet.Type == protocol.PacketTypeFindNodeReply {
				var fr protocol.FindNodeReplyPayload
				if err := json.Unmarshal(packet.Payload, &fr); err != nil {
					continue
				}
				d.handleFindNodeReply(fr)
				continue
			}

			// Reticulum-style announce: verify, learn the node + its path, and
			// (if we are a transport) re-flood it.
			if packet.Type == protocol.PacketTypeAnnounce {
				d.handleAnnounce(remoteAddr, srcIface, &packet)
				continue
			}

			// Path request: answer with the destination's announce if we can, or
			// (as a transport) flood it one hop further.
			if packet.Type == protocol.PacketTypePathRequest {
				d.handlePathRequest(&packet)
				continue
			}

			// AutoNAT dial-back: a check asks us to connect to the sender's data
			// port (dial runs in a goroutine so it never blocks the read loop); a
			// result reports the outcome of our own request.
			if packet.Type == protocol.PacketTypeReachabilityCheck {
				var rp protocol.ReachabilityPayload
				if err := json.Unmarshal(packet.Payload, &rp); err != nil {
					continue
				}
				go d.handleReachabilityCheck(remoteAddr, rp)
				continue
			}
			if packet.Type == protocol.PacketTypeReachabilityResult {
				var rp protocol.ReachabilityPayload
				if err := json.Unmarshal(packet.Payload, &rp); err != nil {
					continue
				}
				d.handleReachabilityResult(rp)
				continue
			}

			var payload protocol.DiscoveryPayload
			if err := json.Unmarshal(packet.Payload, &payload); err != nil {
				continue
			}

			// Key-binding: an advertised identity is only trusted if the node's
			// ID is derived from the same Ed25519 key that signed the packet.
			// This makes impersonation infeasible without the private key.
			signerID := packet.SignerID()
			bound := payload.NodeID == signerID && packet.SourceNode == signerID

			switch packet.Type {
			case protocol.PacketTypeDiscovery:
				if !bound {
					continue
				}
				d.updateNode(payload.NodeID, remoteAddr.String(), payload.PubKey, packet.SignerKey, payload.Port, payload.Capabilities, payload.RelayIDs, payload.MLKEMPub)

			case protocol.PacketTypeLatencyCheck:
				if !bound {
					continue
				}
				// Reply to the requester, echoing the nonce so it can
				// correlate the reply with its outstanding request.
				d.updateNode(payload.NodeID, remoteAddr.String(), payload.PubKey, packet.SignerKey, payload.Port, payload.Capabilities, payload.RelayIDs, payload.MLKEMPub)
				d.sendLatencyReply(payload.NodeID, remoteAddr, payload.Nonce)

			case protocol.PacketTypeLatencyReply:
				// The reply echoes the address the peer observed us at; record it
				// so we can learn our own public (reflexive) address.
				if payload.ObservedAddr != "" {
					d.recordObserved(payload.ObservedAddr)
				}
				// Deliver the arrival time to the waiting measureLatency call — but
				// only if the reply came from the node we actually probed. The
				// signer is authenticated (the packet passed Verify above) and node
				// IDs are key-derived, so this rejects a reply from a *different*
				// node answering at the same address, which would otherwise keep a
				// stale identity alive forever.
				d.pendingMu.Lock()
				p, ok := d.pending[payload.Nonce]
				d.pendingMu.Unlock()
				if ok && p.nodeID == packet.SignerID() {
					select {
					case p.ch <- time.Now():
					default:
					}
				}
			}
		}
	}
}

// sendLatencyReply responds to a latency check from nodeID at addr, echoing
// nonce, routed over the interface that reaches nodeID.
func (d *Discovery) sendLatencyReply(nodeID string, addr *net.UDPAddr, nonce uint64) {
	payload := &protocol.DiscoveryPayload{
		NodeID:       d.selfID,
		Version:      "1.0.0",
		Nonce:        nonce,
		ObservedAddr: addr.String(), // tell the requester where we saw it
	}

	packetData, _ := json.Marshal(payload)
	packet := protocol.NewPacket(protocol.PacketTypeLatencyReply, packetData, "ANY", "")
	packet.SourceNode = d.selfID
	packet.Sign(d.signPriv)

	packetBytes, _ := packet.MarshalBinary()
	d.ifaceFor(nodeID).Send(addr.String(), packetBytes)
}

// maintainPeers periodically checks node health and discovers new peers
func (d *Discovery) maintainPeers() {
	discoveryTicker := time.NewTicker(baseDiscoveryInterval)
	latencyTicker := time.NewTicker(latencyCheckInterval)
	gossipTicker := time.NewTicker(gossipInterval)
	reachTicker := time.NewTicker(reachCheckInterval)
	defer gossipTicker.Stop()
	defer reachTicker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-discoveryTicker.C:
			d.broadcastDiscovery()
			d.announceSelf() // Reticulum-style flooded announce, same cadence
			d.sendBootstrapDiscovery()
			d.adjustDiscoveryInterval(discoveryTicker)
		case <-latencyTicker.C:
			d.checkLatencies()
		case <-gossipTicker.C:
			d.gossipPeers()
			d.refreshDHT()
			d.savePeerCache()       // persist known peers so restarts re-bootstrap from them
			d.checkBridgeLiveness() // warn about a bridge that connected but carries no traffic
		case <-reachTicker.C:
			d.reachMu.Lock()
			enabled := d.reachEnabled
			d.reachMu.Unlock()
			if enabled {
				go d.checkReachability()
			}
		}
	}
}

// refreshDHT runs a self-lookup to keep the Kademlia buckets populated as the
// swarm changes. No-op when the DHT is disabled or no contacts are known yet.
func (d *Discovery) refreshDHT() {
	if d.rt == nil || d.rt.Len() == 0 {
		return
	}
	self := d.rt.Self()
	go d.rt.Lookup(self, dht.DefaultK, dht.DefaultAlpha, dht.DefaultMaxRounds, func(c dht.Contact) []dht.Contact {
		return d.sendFindNode(c, self.String())
	})
}

// updateNode adds or updates a node in the registry. The pubKey/port/caps
// arguments carry the identity/routing information advertised in the discovery
// payload; empty/zero values leave any previously learned data untouched.
func (d *Discovery) updateNode(nodeID, addr string, pubKey, signKey []byte, port uint16, capabilities, relayIDs []string, mlkemPub []byte) {
	d.upsertNode(nodeID, addr, pubKey, signKey, port, capabilities, relayIDs, mlkemPub, true)
}

// learnCandidate records a node we heard about from a third party (a DHT
// FIND_NODE contact list) rather than from the node itself. It learns identity
// and metadata — the (ID, key) binding is verified by the caller — but does NOT
// assert liveness: the peer is admitted unverified and only becomes active by
// answering our own authenticated latency check.
//
// Without this split, every 30s DHT refresh re-activated peers that the latency
// round had just demoted, so dead nodes oscillated in and out of the routing set
// forever. Liveness is first-hand only.
func (d *Discovery) learnCandidate(nodeID, addr string, pubKey, signKey []byte, port uint16, capabilities, relayIDs []string, mlkemPub []byte) {
	d.upsertNode(nodeID, addr, pubKey, signKey, port, capabilities, relayIDs, mlkemPub, false)
}

// upsertNode is the single chokepoint for adding/updating a peer. verified says
// whether the caller has first-hand, authenticated proof the node is alive right
// now (it signed a packet we received from it) — only then may liveness be set.
func (d *Discovery) upsertNode(nodeID, addr string, pubKey, signKey []byte, port uint16, capabilities, relayIDs []string, mlkemPub []byte, verified bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if nodeID == d.selfID {
		return
	}

	if node, exists := d.nodes[nodeID]; exists {
		if verified {
			node.LastSeen = time.Now()
			node.Active = true
			node.Address = addr
		} else if node.Address == "" && addr != "" {
			// Filling a blank is not overwriting. A peer first heard of through a
			// forwarded announce is recorded with no address at all; refusing every
			// unverified address then leaves it permanently unroutable, because the
			// DHT contact list that could resolve it is unverified too. The peer
			// still stays inactive until it answers our own latency check, so this
			// grants reachability information, never liveness.
			node.Address = addr
		}
		if len(pubKey) > 0 {
			node.PubKey = pubKey
		}
		if len(signKey) > 0 {
			node.SignKey = signKey
		}
		if port != 0 {
			node.Port = port
		}
		if len(capabilities) > 0 {
			node.Capabilities = capabilities
		}
		if len(mlkemPub) > 0 {
			node.MLKEMPub = mlkemPub
		}
		// nil means "this message carries no reservation information", not "the
		// peer has none". Announces cannot carry RelayIDs at all (AnnouncePayload
		// has no such field) and pass nil — so assigning unconditionally let every
		// announce WIPE the reservation relays a discovery packet had just
		// advertised. A NAT'd node's circuit reservation was therefore erased about
		// as fast as it was published, senders never saw a relay to route the final
		// hop through, and delivery to any NAT'd peer quietly failed. An explicit
		// empty (non-nil) list still clears them, which is how a node that has
		// dropped its reservations says so — in practice an *empty* list is also
		// treated as "no information", because JSON round-trips make nil and []
		// indistinguishable in places. Stale RelayIDs are harmless: CircuitReachable
		// requires the named relay to be verified and active, and a send through a
		// dead circuit fails and surfaces via ConfirmDelivery.
		if len(relayIDs) > 0 {
			node.RelayIDs = relayIDs
		}
	} else {
		if !d.admitLocked(addr) {
			return // table/subnet full of fresher peers; resist eclipse
		}
		d.nodes[nodeID] = &Node{
			ID:      nodeID,
			Address: addr,
			// An unverified candidate is admitted but stays out of routing until
			// it answers a latency check itself.
			LastSeen:     time.Now(),
			Active:       verified,
			PubKey:       pubKey,
			SignKey:      signKey,
			Port:         port,
			Capabilities: capabilities,
			RelayIDs:     relayIDs,
			MLKEMPub:     mlkemPub,
		}
		d.joins++
	}

	// Record the sighting in the Kademlia routing table using the UDP address it
	// was seen at, so FIND_NODE can reach it.
	d.rtUpdate(nodeID, addr, port)
}

// attestedOnly returns v when the record it came from was signed by its own
// subject, and nil otherwise — so a third party's claim about someone else's
// capabilities or reservation relays is dropped rather than believed.
func attestedOnly(selfAttested bool, v []string) []string {
	if !selfAttested {
		return nil
	}
	return v
}

// mergePeer folds a gossiped PeerInfo record into the node table. It adds
// previously unknown peers, refreshes LastSeen and identity fields for known
// ones, never regresses a node to staler data, and skips the local node.
//
// selfAttested means this record describes the peer that signed the gossip
// message — a first-party statement, carrying the same authority as a direct
// discovery packet. Only such a record may set Capabilities and RelayIDs; for
// anyone else those fields are an unverifiable claim about a third party (see
// SECURITY_AUDIT.md finding 2).
func (d *Discovery) mergePeer(pi protocol.PeerInfo, selfAttested bool) {
	if pi.NodeID == "" || pi.NodeID == d.selfID {
		return
	}

	// Key-binding: reject any gossiped record whose ID is not derived from its
	// advertised signing key, so gossip cannot inject a spoofed (ID, key) pair.
	if pi.NodeID != protocol.DeriveNodeID(pi.SignKey) {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if node, exists := d.nodes[pi.NodeID]; exists {
		// Do not overwrite a node with older information than we already hold.
		if pi.LastSeen.Before(node.LastSeen) {
			return
		}
		// Deliberately NOT updating LastSeen or Active here. Gossip is a third
		// party's claim about a peer, not evidence the peer is alive: a dead node
		// would otherwise be resurrected forever by whoever still gossips it (two
		// peers can keep each other's stale entries alive indefinitely), and an
		// entry marked active is eligible for routing — where traffic sealed to a
		// departed node's key becomes a silent black hole. Liveness is first-hand
		// only, established by an authenticated latency check. Metadata below is
		// safe to learn from gossip because the (ID, key) binding was verified
		// above.
		if pi.Address != "" {
			node.Address = pi.Address
		}
		if len(pi.PubKey) > 0 {
			node.PubKey = pi.PubKey
		}
		if len(pi.SignKey) > 0 {
			node.SignKey = pi.SignKey
		}
		if pi.Port != 0 {
			node.Port = pi.Port
		}
		if selfAttested && len(pi.Capabilities) > 0 {
			node.Capabilities = pi.Capabilities
		}
		if len(pi.MLKEMPub) > 0 {
			node.MLKEMPub = pi.MLKEMPub
		}
		// Only a non-empty list carries information: an omitted list means "this
		// message says nothing about reservations", not "the peer has none".
		if selfAttested && len(pi.RelayIDs) > 0 {
			node.RelayIDs = pi.RelayIDs
		}
		return
	}

	if !d.admitLocked(pi.Address) {
		return // resist gossip-driven eclipse
	}
	lastSeen := pi.LastSeen
	if lastSeen.IsZero() {
		lastSeen = time.Now()
	}
	d.nodes[pi.NodeID] = &Node{
		ID:      pi.NodeID,
		Address: pi.Address,
		// Admitted as a candidate, not as a live peer: a gossiped node is
		// unverified until it answers an authenticated latency check itself
		// (checkLatencies promotes it). Until then it is not routed through.
		LastSeen: lastSeen,
		Active:   false,
		PubKey:   pi.PubKey,
		SignKey:  pi.SignKey,
		Port:     pi.Port,
		// Third-party records contribute identity only; a first-party one may also
		// state what it is and how to reach it.
		Capabilities: attestedOnly(selfAttested, pi.Capabilities),
		RelayIDs:     attestedOnly(selfAttested, pi.RelayIDs),
		MLKEMPub:     pi.MLKEMPub,
	}
	d.joins++
}

// checkLatencies measures latency to all known peers
func (d *Discovery) checkLatencies() {
	d.mu.RLock()
	nodes := make([]*Node, 0, len(d.nodes))
	// Unverified peers are ones we only know from gossip. They are probed too,
	// because a first-hand check is now the *only* way a peer becomes active —
	// without this they could never be used. Bounded per round so a table full of
	// stale entries cannot stall the loop (each probe costs up to maxLatency).
	unverified := make([]*Node, 0, maxVerifyPerRound)
	for _, node := range d.nodes {
		if node.Active {
			nodes = append(nodes, node)
		} else if len(unverified) < maxVerifyPerRound {
			unverified = append(unverified, node)
		}
	}
	d.mu.RUnlock()

	// Probe concurrently, bounded. Each unreachable peer costs a full maxLatency
	// timeout, so a sequential sweep scaled with the table: ~40s for 20 peers and
	// ~17 minutes at maxPeers, during which nothing got re-verified. That matters
	// more now that a first-hand probe is the only way a peer becomes active.
	var wg sync.WaitGroup
	sem := make(chan struct{}, latencyProbeConcurrency)

	probe := func(node *Node, promote bool) {
		defer wg.Done()
		defer func() { <-sem }()
		latency := d.measureLatency(node)
		d.mu.Lock()
		defer d.mu.Unlock()
		if latency > maxLatency {
			if !promote {
				node.Active = false // an active peer that stopped answering
			}
			return // an unverified candidate simply stays unverified
		}
		node.Latency = latency
		if promote {
			node.Active = true
			node.LastSeen = time.Now()
		}
	}

	for _, node := range nodes {
		wg.Add(1)
		sem <- struct{}{}
		go probe(node, false)
	}
	// Promote a candidate we only know by hearsay once it answers us directly.
	for _, node := range unverified {
		wg.Add(1)
		sem <- struct{}{}
		go probe(node, true)
	}
	wg.Wait()
}

// measureLatency sends a latency check packet to a node and measures the real
// round-trip time. It returns maxLatency (marking the node inactive) if no
// reply arrives within the timeout.
func (d *Discovery) measureLatency(node *Node) time.Duration {
	// Snapshot the fields we need under the lock: the node table (this *Node) is
	// mutated concurrently by updateNode, so reading node.Address/node.ID directly
	// would race.
	d.mu.RLock()
	nodeAddr, nodeID := node.Address, node.ID
	d.mu.RUnlock()

	// A peer reached through a bridge, or learned by routing, has no address we can
	// use: a bridge interface writes to its single connection and ignores the
	// address argument, so an interface-addressed check would be delivered to the
	// bridge peer, which answers as itself and is correctly rejected by
	// identity-bound liveness. Such peers could therefore never be verified. Route
	// the check by destination instead.
	addr, addrErr := net.ResolveUDPAddr("udp", nodeAddr)
	viaRoute := nodeAddr == "" || addrErr != nil || d.routedOnly(nodeID)
	if !viaRoute && addr == nil {
		return maxLatency + time.Nanosecond
	}

	// Register a channel keyed on a unique nonce so listenForPeers can deliver
	// the reply back to us.
	nonce := d.nonceCounter.Add(1)
	replyCh := make(chan time.Time, 1)

	d.pendingMu.Lock()
	d.pending[nonce] = pendingLatency{nodeID: nodeID, ch: replyCh}
	d.pendingMu.Unlock()

	defer func() {
		d.pendingMu.Lock()
		delete(d.pending, nonce)
		d.pendingMu.Unlock()
	}()

	payload := &protocol.DiscoveryPayload{
		NodeID:  d.selfID,
		Version: "1.0.0",
		Nonce:   nonce,
	}

	packetData, _ := json.Marshal(payload)
	packet := protocol.NewPacket(protocol.PacketTypeLatencyCheck, packetData, "ANY", node.ID)
	packet.SourceNode = d.selfID
	packet.Sign(d.signPriv)

	packetBytes, _ := packet.MarshalBinary()

	start := time.Now()
	sent := false
	if viaRoute {
		sent = d.SendRoutedDiscovery(nodeID, packetBytes, 0)
		// Also try the primary datagram interface when we have an address. Hearing
		// a peer over a bridge does not mean it is *only* reachable that way — a
		// public relay is reachable by UDP too, and it was being marked
		// bridge-only purely because its announce last crossed the bridge. Falling
		// back to ifaceFor here would be pointless: that is the bridge, which
		// cannot address anything but its own far end. Both probes carry the same
		// nonce, so whichever arrives first verifies the peer and the other is
		// ignored.
		if addr != nil && d.iface != nil {
			if err := d.iface.Send(addr.String(), packetBytes); err == nil {
				sent = true
			}
		}
	} else if addr != nil {
		sent = d.ifaceFor(nodeID).Send(addr.String(), packetBytes) == nil
	}
	if !sent {
		return maxLatency + time.Nanosecond
	}

	timer := time.NewTimer(maxLatency)
	defer timer.Stop()

	select {
	case arrival := <-replyCh:
		return arrival.Sub(start)
	case <-timer.C:
		// No reply in time: report a latency that marks the node inactive.
		return maxLatency + time.Nanosecond
	case <-d.ctx.Done():
		return maxLatency
	}
}

// adjustDiscoveryInterval modifies the discovery interval based on network size
func (d *Discovery) adjustDiscoveryInterval(ticker *time.Ticker) {
	d.mu.RLock()
	activeNodes := 0
	for _, node := range d.nodes {
		if node.Active {
			activeNodes++
		}
	}
	d.mu.RUnlock()

	// If we have fewer than minNodes, reset to base interval
	if activeNodes < minNodes {
		ticker.Reset(baseDiscoveryInterval)
		return
	}

	// Increase interval based on number of active nodes, up to maxDiscoveryInterval
	interval := baseDiscoveryInterval * time.Duration(activeNodes)
	if interval > maxDiscoveryInterval {
		interval = maxDiscoveryInterval
	}
	ticker.Reset(interval)
}

// GetActiveNodes returns a list of currently active nodes
func (d *Discovery) GetActiveNodes() []*Node {
	d.mu.RLock()
	defer d.mu.RUnlock()

	nodes := make([]*Node, 0)
	for _, node := range d.nodes {
		if node.Active {
			nodeCopy := *node
			nodes = append(nodes, &nodeCopy)
		}
	}
	return nodes
}

// AllNodes returns a snapshot of every peer in the table — active or not — as
// copies, so an operator can also see peers that have gone quiet (an inactive
// entry is often the interesting one when diagnosing a partition).
func (d *Discovery) AllNodes() []*Node {
	d.mu.RLock()
	defer d.mu.RUnlock()

	nodes := make([]*Node, 0, len(d.nodes))
	for _, node := range d.nodes {
		nodeCopy := *node
		nodes = append(nodes, &nodeCopy)
	}
	return nodes
}

// discoveryPacketBytes builds and signs a discovery packet advertising the
// local node's identity (pubkey/port/capabilities set via SetIdentity).
func (d *Discovery) discoveryPacketBytes() []byte {
	d.mu.RLock()
	payload := &protocol.DiscoveryPayload{
		NodeID:       d.selfID,
		Version:      "1.0.0",
		PubKey:       d.pubKey,
		SignKey:      d.signPub,
		Port:         d.port,
		Capabilities: d.capabilities,
		RelayIDs:     d.relayIDs,
		MLKEMPub:     d.mlkemPub,
	}
	d.mu.RUnlock()

	packetData, _ := json.Marshal(payload)
	packet := protocol.NewPacket(protocol.PacketTypeDiscovery, packetData, "ANY", "")
	packet.SourceNode = d.selfID
	packet.Sign(d.signPriv)

	packetBytes, _ := packet.MarshalBinary()
	return packetBytes
}

// broadcastDiscovery sends a discovery packet to the network
func (d *Discovery) broadcastDiscovery() {
	d.floodFrame(d.discoveryPacketBytes()) // fan out across every interface (incl. bridges)
}

// sendBootstrapDiscovery unicasts a discovery packet to each configured
// bootstrap peer so a fresh node can join without relying on broadcast.
func (d *Discovery) sendBootstrapDiscovery() {
	d.mu.RLock()
	addrs := append([]string(nil), d.bootstrapPeers...)
	d.mu.RUnlock()

	if len(addrs) == 0 {
		return
	}

	packetBytes := d.discoveryPacketBytes()
	resolved := 0
	for _, a := range addrs {
		udpAddr, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			continue
		}
		resolved++
		d.iface.Send(udpAddr.String(), packetBytes)
	}
	// If not a single bootstrap/seed address resolved, the node can never join
	// via them (e.g. a seed DNS record that doesn't exist). Warn once so this
	// otherwise-invisible failure is self-diagnosing.
	if resolved == 0 && d.bootstrapWarned.CompareAndSwap(false, true) {
		log.Printf("discovery: none of %d bootstrap/seed addresses resolved (%v) — node cannot join via them; check DNS/config", len(addrs), addrs)
	} else if resolved > 0 {
		d.bootstrapWarned.Store(false)
	}
}

// buildPeerExchangePayload assembles the local view of the swarm for gossip:
// the local node (with its advertised identity) plus all active known nodes.
func (d *Discovery) buildPeerExchangePayload() protocol.PeerExchangePayload {
	d.mu.RLock()
	defer d.mu.RUnlock()

	peers := make([]protocol.PeerInfo, 0, len(d.nodes)+1)

	// Advertise self first so peers learn our identity via gossip too.
	peers = append(peers, protocol.PeerInfo{
		NodeID:       d.selfID,
		PubKey:       d.pubKey,
		SignKey:      d.signPub,
		Port:         d.port,
		Capabilities: d.capabilities,
		RelayIDs:     d.relayIDs,
		MLKEMPub:     d.mlkemPub,
		LastSeen:     time.Now(),
	})

	for _, node := range d.nodes {
		if !node.Active {
			continue
		}
		// Third-party records carry identity and address only. Capabilities and
		// RelayIDs are omitted: we cannot attest to them for someone else, and
		// relaying them would only amplify a claim the receiver must ignore
		// anyway. Peers learn both from the subject's own signed announce. (Our
		// *own* entry above still carries them, which costs nothing and keeps
		// pre-announce-RelayIDs peers working.)
		peers = append(peers, protocol.PeerInfo{
			NodeID:   node.ID,
			Address:  node.Address,
			PubKey:   node.PubKey,
			SignKey:  node.SignKey,
			Port:     node.Port,
			MLKEMPub: node.MLKEMPub,
			LastSeen: node.LastSeen,
		})
	}

	return protocol.PeerExchangePayload{Peers: peers}
}

// gossipPeers sends the local peer view to a bounded set of known peers.
func (d *Discovery) gossipPeers() {
	px := d.buildPeerExchangePayload()
	packetData, _ := json.Marshal(px)

	// Pick a bounded set of active, addressable peers to gossip to, keeping each
	// peer's ID so the message routes over the interface that reaches it.
	type target struct{ id, addr string }
	d.mu.RLock()
	targets := make([]target, 0, maxGossipPeers)
	for _, node := range d.nodes {
		if !node.Active || node.Address == "" {
			continue
		}
		targets = append(targets, target{id: node.ID, addr: node.Address})
		if len(targets) >= maxGossipPeers {
			break
		}
	}
	d.mu.RUnlock()

	for _, tg := range targets {
		udpAddr, err := net.ResolveUDPAddr("udp", tg.addr)
		if err != nil {
			continue
		}
		packet := protocol.NewPacket(protocol.PacketTypePeerExchange, packetData, "ANY", "")
		packet.SourceNode = d.selfID
		packet.Sign(d.signPriv)
		packetBytes, _ := packet.MarshalBinary()
		d.ifaceFor(tg.id).Send(udpAddr.String(), packetBytes)
	}
}
