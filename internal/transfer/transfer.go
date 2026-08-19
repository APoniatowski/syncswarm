package transfer

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/APoniatowski/syncswarm/internal/discovery"
	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/fragment"
	"github.com/APoniatowski/syncswarm/internal/monitoring"
	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/routing"
	"github.com/APoniatowski/syncswarm/internal/storage"
)

const (
	maxChunkSize = 1024 * 1024 // 1MB chunks
	// maxSubChunkSize caps a single fragment's on-wire payload. Reed-Solomon
	// shards for a large payload can be many megabytes each; a shard larger than
	// this is split into transport-sized sub-chunks (see fragmentPieces) so no
	// single packet is huge, and reassembled before RS reconstruction. Set
	// comfortably above a sealed sequential chunk (maxChunkSize + AEAD overhead)
	// so ordinary chunks are never split.
	maxSubChunkSize = 4 * 1024 * 1024 // 4MB wire cap per fragment
	transferPort    = 64513           // Port for data transfer (one above discovery)
	maxRetries      = 3
	retryDelay      = time.Second * 2

	ackTimeout     = time.Second * 3 // wait for a delivery ack before resending
	maxAckAttempts = 3               // resend attempts before giving up on confirmation
)

// DataPort is the TCP port this package listens on for data/relay traffic.
// Exported so callers (e.g. swarmsync) can advertise it to peers.
const DataPort = transferPort

// Transfer handles the data transfer between nodes
type Transfer struct {
	discovery *discovery.Discovery
	storage   *storage.Storage
	selfID    string
	sealer    encryption.Sealer  // non-nil when a developer key is configured
	onData    func([]byte, bool) // delivery callback; bool = payload is a gob variable
	nodePriv  *ecdh.PrivateKey   // this node's X25519 key, used to peel forwarded layers

	// sealToRecipient enables per-recipient end-to-end sealing: a targeted send to
	// a keyed node seals fragments to that node's public key instead of a shared
	// symmetric Key, and the receiver opens them with nodePriv.
	sealToRecipient bool
	// postQuantum, when set with sealToRecipient, uses hybrid X25519 + ML-KEM-768
	// sealing to a recipient that advertises an ML-KEM key. mlkemDecap is this
	// node's ML-KEM decapsulation key, used to open PQ-sealed fragments.
	postQuantum bool
	mlkemDecap  *mlkem.DecapsulationKey768

	signKey      ed25519.PrivateKey // this node's Ed25519 identity key, signs outgoing packets
	hopCount     int                // intermediary hops per fragment (0 = direct)
	redundancy   int                // independent paths sent per fragment (>=1)
	dataShards   int                // Reed-Solomon data shards (0 = plain sequential chunks)
	parityShards int                // Reed-Solomon parity shards
	subChunkSize int                // wire cap per fragment; larger fragments are sub-chunked

	// Streaming (block-wise RS): SendStream cuts the payload into blocks of
	// streamBlockSize so neither end buffers it whole; streamSink, when set,
	// receives completed blocks in order (else the stream is buffered and
	// delivered via onData).
	streamBlockSize int
	streamSink      func(id [32]byte) io.WriteCloser
	confirm         bool   // wait for end-to-end delivery acks and resend
	dataPort        int    // actual TCP port this node listens on
	selfHost        string // host part of this node's own reachable address
	listener        net.Listener
	ctx             context.Context
	cancel          context.CancelFunc
	transfers       sync.Map // Track ongoing transfers

	// pendingAcks maps a transfer ID to a channel closed when the destination's
	// end-to-end acknowledgement for that transfer arrives.
	ackMu       sync.Mutex
	pendingAcks map[[32]byte]*pendingAck

	// needsRelay marks this node as unable to accept inbound connections (e.g.
	// behind NAT): it holds circuit reservations with relays instead. Atomic
	// because AutoNAT (autoRelay) may toggle it at runtime from the discovery
	// goroutine while the reservation loop reads it.
	needsRelay atomic.Bool
	// autoRelay runs the reservation loop even when needsRelay starts false, so
	// AutoNAT can enable reservations later by flipping needsRelay.
	autoRelay bool

	// strictAnon makes an anonymous send (HopCount > 0) that cannot build a
	// forwarded route fail rather than silently fall back to a direct send (which
	// would reveal the sender's address to the recipient). Opt-in.
	strictAnon bool

	// Anonymity hardening (Round 8).
	coverTraffic bool          // emit indistinguishable decoy traffic
	padCell      int           // pad inner packets up to a multiple of this many bytes (0 = off)
	relayJitter  time.Duration // max random delay a relay adds before forwarding

	// Store-and-forward (Round 10): a relay holds undeliverable fragments for an
	// offline recipient and flushes them when the recipient reconnects/reserves.
	storeForward bool
	offlineTTL   time.Duration
	offMu        sync.Mutex
	offline      map[string][]pendingBlob
	offSeq       atomic.Uint64 // monotonic sequence naming persisted offline blobs

	metrics *monitoring.Metrics // nil-safe activity counters
	tracer  hopTracer           // opt-in local hop-event ring (observability)

	pool *connPool // reused outbound connections for one-shot forwarded packets

	// Relay reputation (Round 9 follow-up): each relay is periodically challenged
	// to forward a self-addressed probe; a relay that fails strikeLimit
	// consecutive challenges is excommunicated (excluded from routing) for the
	// penance duration. The challenge is sealed to us, so a relay cannot fake
	// passing it.
	relayScoring bool
	strikeLimit  int
	penance      time.Duration
	repMu        sync.Mutex
	relayStrikes map[string]int
	excommunions map[string]time.Time // relay ID -> time the excommunication lifts

	probeMu sync.Mutex
	probes  map[[32]byte]chan struct{}

	// reservations holds, on a relay, the open connections of nodes that reserved
	// through us (nodeID -> connection), so we can forward their inbound traffic.
	resMu              sync.Mutex
	reservations       map[string]*reservedConn
	reservedIDs        map[string]bool // relay NodeIDs we hold live reservations with
	reservationClients map[string]bool // relays we've started a reservation loop for
}

// pendingBlob is a stored onion blob awaiting an offline recipient. seq names
// its on-disk file so it can be deleted individually once delivered or expired.
type pendingBlob struct {
	seq    uint64
	blob   []byte
	expiry time.Time
}

// reservedConn is a held connection to a node that reserved through this relay.
type reservedConn struct {
	mu   sync.Mutex // serializes writes to the shared connection
	conn net.Conn
}

// scheme describes how a transfer's payload was fragmented, so the receiver can
// reassemble it. A zero DataShards means plain sequential chunking.
type scheme struct {
	DataShards   uint32
	ParityShards uint32
	OriginalLen  uint64
	Variable     bool
	Streaming    bool // block-wise erasure coding: reassemble and flush per block
	HybridSealed bool // fragments sealed to the recipient's key, not a shared key
	PQ           bool // HybridSealed uses post-quantum hybrid (X25519 + ML-KEM-768)
	Resumable    bool // streaming transfer whose receiver retains partial progress
}

// transferState tracks the state of an ongoing transfer
type transferState struct {
	ID          [32]byte
	Total       uint32                       // Total fragments/shards expected
	TotalChunks uint32                       // Retained alias of Total for existing callers
	Received    map[uint32]bool              // Which 0-based logical indices are fully present
	Chunks      map[uint32][]byte            // 0-based logical index -> (possibly sealed) payload
	subParts    map[uint32]map[uint32][]byte // logical index -> sub-chunk index -> piece (until whole)
	Meta        *storage.ChunkMeta
	StartTime   time.Time
	scheme      scheme // fragmentation scheme (RS metadata + variable flag)
	sourceNode  string // origin node ID (direct, non-anonymous acks)
	replyBlock  []byte // anonymous onion return path for the delivery ack

	// stream is set for block-wise streaming transfers (scheme.Streaming); when
	// non-nil, fragments are routed to it and reassembled/flushed per block
	// instead of buffering the whole payload.
	stream *streamAssembler

	// mu guards Received/Chunks/delivered when fragments for the same transfer
	// arrive concurrently over separate connections (the forwarded path).
	mu        sync.Mutex
	delivered bool
}

// NewTransfer creates a new transfer service. When key is non-empty it must be a
// valid AES-256 key; every fragment is then sealed so relays see only
// ciphertext. onData, when set, receives each fully reassembled payload. nodePriv
// is this node's X25519 private key used to peel forwarded layers; hopCount is
// the number of intermediary hops to route each fragment through (0 = direct);
// redundancy is the number of independent paths each fragment is sent over
// (values < 1 are treated as 1); dataShards/parityShards enable Reed-Solomon
// erasure coding when both are > 0 (requires a key); dataPort is the TCP port to
// listen on (0 requests an ephemeral port, read back with Port()).
func NewTransfer(disc *discovery.Discovery, store *storage.Storage, selfID string, key []byte, onData func([]byte, bool), nodePriv *ecdh.PrivateKey, signKey ed25519.PrivateKey, hopCount, redundancy, dataShards, parityShards int, confirm bool, dataPort int) (*Transfer, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", dataPort))
	if err != nil {
		return nil, fmt.Errorf("failed to start transfer listener: %w", err)
	}
	if redundancy < 1 {
		redundancy = 1
	}

	var sealer encryption.Sealer
	if len(key) != 0 {
		// Length is validated upstream in swarmsync.New; NewAEADSealer also
		// rejects a wrong-sized key, so a nil sealer here means plaintext.
		sealer, _ = encryption.NewAEADSealer(key)
	}

	// Erasure coding requires a sealer (the RS fragmenter seals each shard).
	if sealer == nil {
		dataShards, parityShards = 0, 0
	}

	ctx, cancel := context.WithCancel(context.Background())

	t := &Transfer{
		discovery:          disc,
		storage:            store,
		selfID:             selfID,
		sealer:             sealer,
		onData:             onData,
		nodePriv:           nodePriv,
		signKey:            signKey,
		hopCount:           hopCount,
		redundancy:         redundancy,
		dataShards:         dataShards,
		parityShards:       parityShards,
		subChunkSize:       maxSubChunkSize,
		streamBlockSize:    defaultStreamBlockSize,
		confirm:            confirm,
		dataPort:           listener.Addr().(*net.TCPAddr).Port,
		selfHost:           selfDialHost(),
		listener:           listener,
		ctx:                ctx,
		cancel:             cancel,
		pendingAcks:        make(map[[32]byte]*pendingAck),
		reservations:       make(map[string]*reservedConn),
		reservedIDs:        make(map[string]bool),
		reservationClients: make(map[string]bool),
		offline:            make(map[string][]pendingBlob),
		relayStrikes:       make(map[string]int),
		excommunions:       make(map[string]time.Time),
		probes:             make(map[[32]byte]chan struct{}),
		pool:               newConnPool(),
	}

	return t, nil
}

// sendPooled writes pkt to addr over a reused connection when possible, falling
// back to a fresh dial. On success the connection is returned to the pool for
// the next one-shot forwarded packet.
func (t *Transfer) sendPooled(addr string, pkt *protocol.Packet) error {
	if c := t.pool.get(addr); c != nil {
		if err := protocol.WritePacket(c, pkt); err == nil {
			t.pool.put(addr, c)
			return nil
		}
		c.Close() // stale connection; dial a fresh one
	}
	conn := dialWithRetries(addr)
	if conn == nil {
		return fmt.Errorf("failed to reach %s", addr)
	}
	if err := protocol.WritePacket(conn, pkt); err != nil {
		conn.Close()
		return err
	}
	t.pool.put(addr, conn)
	return nil
}

// reapPool periodically closes idle pooled connections.
func (t *Transfer) reapPool() {
	ticker := time.NewTicker(poolReapEvery)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.pool.reap()
		}
	}
}

// SetRelayScoring enables periodic relay liveness challenges. A relay that fails
// strikeLimit consecutive challenges is excommunicated (excluded from routing)
// for the penance duration; a single success absolves it. Call before Start.
func (t *Transfer) SetRelayScoring(enabled bool, strikeLimit int, penance time.Duration) {
	t.relayScoring = enabled
	if strikeLimit <= 0 {
		strikeLimit = defaultStrikeLimit
	}
	t.strikeLimit = strikeLimit
	if penance <= 0 {
		penance = defaultPenance
	}
	t.penance = penance
}

// SetNeedsRelay marks whether this node must be reached via circuit relays. Safe
// to call at runtime (AutoNAT toggles it based on reachability).
func (t *Transfer) SetNeedsRelay(v bool) { t.needsRelay.Store(v) }

// SetAutoRelay keeps the reservation loop running even when needsRelay starts
// false, so AutoNAT can enable reservations later. Call before Start.
func (t *Transfer) SetAutoRelay(v bool) { t.autoRelay = v }

// SetSealToRecipient enables per-recipient end-to-end content sealing for
// targeted sends. Call before Start.
func (t *Transfer) SetSealToRecipient(v bool) { t.sealToRecipient = v }

// SetStrictAnonymity makes an anonymous send (HopCount > 0) that cannot build a
// forwarded route return an error instead of silently degrading to a direct send.
// Call before Start.
func (t *Transfer) SetStrictAnonymity(v bool) { t.strictAnon = v }

// SetPostQuantum enables hybrid X25519 + ML-KEM-768 sealing (with
// sealToRecipient) and installs this node's ML-KEM decapsulation key for opening
// PQ-sealed fragments. Call before Start.
func (t *Transfer) SetPostQuantum(v bool, decap *mlkem.DecapsulationKey768) {
	t.postQuantum = v
	t.mlkemDecap = decap
}

// SetMetrics attaches a metrics sink for observability. Call before Start.
func (t *Transfer) SetMetrics(m *monitoring.Metrics) { t.metrics = m }

// SetStoreForward configures whether this node (as a relay) holds undeliverable
// fragments for offline recipients and flushes them on reconnect, with the given
// per-fragment TTL. Call before Start.
func (t *Transfer) SetStoreForward(enabled bool, ttl time.Duration) {
	t.storeForward = enabled
	if ttl <= 0 {
		ttl = defaultOfflineTTL
	}
	t.offlineTTL = ttl
}

// SetSubChunkSize overrides the per-fragment wire cap: a fragment (typically a
// large Reed-Solomon shard) whose payload exceeds this is split into
// transport-sized sub-chunks and reassembled by the receiver. A non-positive
// value restores the default. Call before Start.
func (t *Transfer) SetSubChunkSize(size int) {
	if size <= 0 {
		size = maxSubChunkSize
	}
	t.subChunkSize = size
}

// SetAnonymity configures traffic-analysis defenses: cover traffic (decoy
// packets), padding inner packets up to a padCell-byte boundary, and a random
// per-relay forwarding delay of up to jitter. Call before Start.
func (t *Transfer) SetAnonymity(coverTraffic bool, padCell int, jitter time.Duration) {
	t.coverTraffic = coverTraffic
	if padCell < 0 {
		padCell = 0
	}
	t.padCell = padCell
	if jitter < 0 {
		jitter = 0
	}
	t.relayJitter = jitter
}

// Port returns the actual TCP port this transfer instance listens on.
func (t *Transfer) Port() int {
	return t.dataPort
}

// peerDialAddr returns the address to dial a node for data transfer: the host
// from the node's (discovery-port) address combined with the data port the node
// advertised. Falls back to the default data port when none was advertised.
func peerDialAddr(node *discovery.Node) string {
	host, _, err := net.SplitHostPort(node.Address)
	if err != nil {
		host = node.Address
	}
	port := int(node.Port)
	if port == 0 {
		port = transferPort
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// Start begins the transfer service
func (t *Transfer) Start() {
	go t.acceptConnections()
	go t.reapPool()
	go t.sweepResumableStreams()
	if t.needsRelay.Load() || t.autoRelay {
		go t.maintainReservations()
	}
	if t.coverTraffic {
		go t.maintainCover()
	}
	if t.storeForward {
		t.loadOffline() // recover blobs held across a restart before serving
		go t.sweepOffline()
		go t.redeliverOffline()
	}
	if t.relayScoring {
		go t.maintainReputation()
	}
}

// Stop halts all transfer activities
func (t *Transfer) Stop() {
	t.cancel()
	t.listener.Close()
	t.pool.closeAll()
}

// resolveDest ensures a specific destination is in the active node set. If it is
// not yet known, it attempts a Kademlia lookup (10.4) to locate it — so having a
// node's ID is enough to reach it, even when it hasn't been discovered locally
// yet. On success the node is learned into the table and the refreshed active set
// is returned; otherwise nodes is returned unchanged. No-op for broadcasts, for
// already-known destinations, or when the DHT is unavailable.
func (t *Transfer) resolveDest(destNode string, nodes []*discovery.Node) []*discovery.Node {
	if destNode == "" {
		return nodes
	}
	for _, n := range nodes {
		if n.ID == destNode {
			return nodes // already known
		}
	}
	if _, found := t.discovery.FindNode(destNode); found {
		return t.discovery.GetActiveNodes()
	}
	// Fall back to a Reticulum-style path request: flood for a path and wait
	// briefly for an announce to establish one, then re-read the node table. This
	// is medium-agnostic (works where a DHT is impractical) and needs no DNS or
	// bootstrap server — "have their ID" -> "can reach them".
	if t.discovery.ResolvePath(destNode, pathResolveTimeout) {
		return t.discovery.GetActiveNodes()
	}
	return nodes
}

// pathResolveTimeout bounds how long a targeted send waits for a flooded path
// request to establish a route to an unknown destination before giving up.
const pathResolveTimeout = 2 * time.Second

// contentSealer picks the content sealer for a targeted send to dest: a
// post-quantum hybrid (X25519 + ML-KEM-768) sealer when enabled and dest
// advertises both keys, else the classical recipient-key hybrid sealer, else the
// shared-key sealer. Returns the sealer plus the hybrid/pq scheme flags.
func (t *Transfer) contentSealer(dest *discovery.Node) (encryption.Sealer, bool, bool) {
	if !t.sealToRecipient || dest == nil || len(dest.PubKey) == 0 {
		return t.sealer, false, false
	}
	xpub, err := ecdh.X25519().NewPublicKey(dest.PubKey)
	if err != nil {
		return t.sealer, false, false
	}
	if t.postQuantum && len(dest.MLKEMPub) > 0 {
		if mlpub, err := encryption.ParseMLKEMPub(dest.MLKEMPub); err == nil {
			return encryption.NewPQHybridSealer(xpub, mlpub, nil, nil), true, true
		}
	}
	return encryption.NewHybridSealer(xpub, nil), true, false
}

// recipientOpener returns the sealer used to open a received transfer, per its
// scheme: PQ hybrid, classical hybrid, or the shared key.
func (t *Transfer) recipientOpener(sc scheme) encryption.Sealer {
	if sc.HybridSealed {
		if sc.PQ {
			return encryption.NewPQHybridSealer(nil, nil, t.nodePriv, t.mlkemDecap)
		}
		return encryption.NewHybridSealer(nil, t.nodePriv)
	}
	return t.sealer
}

// SendData initiates a data transfer to specified destinations. variable marks
// the payload as a gob-encoded value so the receiver routes it to
// OnVariableReceived rather than OnDataReceived.
func (t *Transfer) SendData(data []byte, destGroup, destNode string, variable bool) error {
	// Generate unique ID for this transfer (raw SHA-256).
	id := sha256.Sum256(append(data, []byte(time.Now().String())...))

	// Resolve the destination(s) first — needed both to route and to pick the
	// content sealer. If a specific destination isn't currently known,
	// transparently try to locate it via the DHT before giving up.
	nodes := t.discovery.GetActiveNodes()
	nodes = t.resolveDest(destNode, nodes)
	if len(nodes) == 0 {
		return fmt.Errorf("no active nodes available for transfer")
	}
	byID := make(map[string]*discovery.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	if destNode != "" {
		if _, ok := byID[destNode]; !ok {
			return fmt.Errorf("destination node %s is not active", destNode)
		}
	}

	// Strict anonymity: if hops are requested for a targeted send but no forwarded
	// route can be built, fail here rather than silently degrading to a direct send
	// that would reveal the sender to the recipient. Checked before any side effects.
	if t.strictAnon && destNode != "" && t.hopCount > 0 && t.nodePriv != nil {
		if dest, ok := byID[destNode]; !ok || len(dest.PubKey) == 0 || len(t.relayPeers(nodes, destNode)) == 0 {
			return fmt.Errorf("strict anonymity: no relay route to %s for %d hops", destNode, t.hopCount)
		}
	}

	// Choose the content sealer. In recipient-key mode a targeted send to a keyed
	// node is sealed to that node's public key — per-recipient end-to-end, with no
	// shared key needed; otherwise the shared-key sealer (or plaintext) is used.
	sealer, hybrid, pq := t.contentSealer(byID[destNode])

	// Build the wire fragments and the scheme the receiver needs to reassemble.
	frags, sc, err := t.buildFragments(id, data, variable, sealer)
	if err != nil {
		return fmt.Errorf("failed to build fragments: %w", err)
	}
	sc.HybridSealed = hybrid
	sc.PQ = pq

	meta := &storage.ChunkMeta{
		ID:          id,
		TotalChunks: uint32(len(frags)),
		ChunkSize:   uint32(maxChunkSize),
		Timestamp:   time.Now(),
		DestGroup:   destGroup,
		DestNode:    destNode,
	}

	// Store the plaintext chunks locally first (send-side local storage kept
	// as-is; storage uses 1-based chunk numbers).
	localChunks := fragment.Split(data, maxChunkSize)
	for i, chunk := range localChunks {
		if err := t.storage.SaveChunk(id, uint32(i+1), chunk, meta); err != nil {
			return fmt.Errorf("failed to store chunk %d: %w", i+1, err)
		}
	}

	// Order candidate targets fastest-first via the routing planner. The
	// planner works on decoupled routing.Peer values adapted from discovery.
	ordered, err := (&routing.Planner{}).FastestRoute(destNode, nodesToPeers(nodes))
	if err != nil {
		return fmt.Errorf("failed to plan route: %w", err)
	}

	// ackToken authenticates the anonymous reply-block ack for this transfer; it
	// is embedded (sealed) in the reply block and echoed back to us. Set only
	// when confirming delivery.
	var ackToken []byte

	// sendOnce performs a single delivery attempt: multi-hop forwarding when a
	// hop count is set and a route can be built (wrapping each fragment in
	// per-hop layers so no node on the path sees the whole payload or both ends),
	// otherwise a direct send. Broadcast fans out to all active nodes.
	sendOnce := func() {
		if destNode != "" && t.hopCount > 0 && t.nodePriv != nil {
			if dest, ok := byID[destNode]; ok && len(dest.PubKey) > 0 {
				if err := t.sendForwarded(dest, nodes, id, frags, sc, ackToken); err == nil {
					return
				}
				// Forwarded delivery failed. In strict-anonymity mode do not fall
				// back to a direct send (which would reveal the sender); leave it
				// unsent so a confirmed send retries the anonymous path or errors.
				if t.strictAnon {
					return
				}
			}
		}

		var targets []*discovery.Node
		if destNode != "" {
			targets = []*discovery.Node{byID[destNode]}
		} else {
			for _, p := range ordered {
				if n, ok := byID[p.ID]; ok {
					targets = append(targets, n)
				}
			}
		}

		var wg sync.WaitGroup
		for _, node := range targets {
			wg.Add(1)
			go func(n *discovery.Node) {
				defer wg.Done()
				t.sendToNode(n, id, frags, meta, sc)
			}(node)
		}
		wg.Wait()
	}

	// For a specific destination with delivery confirmation enabled, wait for the
	// destination's end-to-end acknowledgement and resend on timeout. Duplicate
	// fragments are deduplicated by the receiver, so resends are safe.
	if destNode != "" && t.confirm {
		ackToken = randomToken()
		ackCh := t.registerAck(id, byID[destNode].SignKey, ackToken)
		defer t.unregisterAck(id)
		for attempt := 0; attempt < maxAckAttempts; attempt++ {
			sendOnce()
			select {
			case <-ackCh:
				return nil
			case <-time.After(ackTimeout):
			case <-t.ctx.Done():
				return fmt.Errorf("transfer canceled")
			}
		}
		return fmt.Errorf("delivery to %s not confirmed after %d attempts", destNode, maxAckAttempts)
	}

	sendOnce()
	return nil
}

// acceptConnections handles incoming transfer connections
func (t *Transfer) acceptConnections() {
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
			conn, err := t.listener.Accept()
			if err != nil {
				continue
			}
			go t.handleConnection(conn)
		}
	}
}

// handleConnection processes an incoming transfer connection
func (t *Transfer) handleConnection(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)

	// Read initial packet
	packet, err := protocol.ReadPacket(r)
	if err != nil {
		return
	}

	// Drop packets that fail signature verification or whose sender identity is
	// not bound to the key that signed them (impersonation attempt).
	if !packet.Verify() || packet.SourceNode != packet.SignerID() {
		return
	}

	// A reservation opens a persistent circuit: this node acts as a relay and
	// holds the connection open to forward the reserving node's inbound traffic.
	if packet.Type == protocol.PacketTypeReservation {
		t.serveReservation(conn, r, packet.SourceNode)
		return
	}

	// Forwarded relay packets and direct acknowledgements are one-shot, and may
	// arrive back-to-back on a pooled, reused connection. Handle them in a loop,
	// re-verifying each, until the connection closes.
	if packet.Type == protocol.PacketTypeRelay || packet.Type == protocol.PacketTypeAcknowledgement {
		for {
			switch packet.Type {
			case protocol.PacketTypeRelay:
				t.handleRelay(packet)
			case protocol.PacketTypeAcknowledgement:
				// A direct end-to-end delivery ack; accepted only if signed by
				// the expected destination's key (checked in signalAckFrom).
				t.signalAckFrom(packet.ID, packet.SignerKey)
			default:
				return
			}
			packet, err = protocol.ReadPacket(r)
			if err != nil {
				return
			}
			if !packet.Verify() || packet.SourceNode != packet.SignerID() {
				return
			}
		}
	}

	// Check if we should accept this transfer
	if !t.shouldAcceptTransfer(packet) {
		return
	}

	sc := schemeFromPacket(packet)

	// For a resumable stream, reuse any partial assembler retained from an earlier
	// interrupted attempt, so the transfer continues where it left off.
	var state *transferState
	if sc.Resumable && sc.Streaming {
		if v, ok := t.transfers.Load(packet.ID); ok {
			state = v.(*transferState)
			state.StartTime = time.Now() // refresh so the resume sweep leaves it alone
		}
	}
	if state == nil {
		state = &transferState{
			ID:          packet.ID,
			Total:       packet.TotalChunks,
			TotalChunks: packet.TotalChunks,
			Received:    make(map[uint32]bool),
			Chunks:      make(map[uint32][]byte),
			scheme:      sc,
			sourceNode:  packet.SourceNode,
			Meta: &storage.ChunkMeta{
				ID:          packet.ID,
				TotalChunks: packet.TotalChunks,
				ChunkSize:   packet.PayloadSize,
				Timestamp:   time.Now(),
				DestGroup:   packet.DestGroup,
				DestNode:    packet.DestNode,
			},
			StartTime: time.Now(),
		}
		if sc.Streaming {
			state.stream = t.newStreamAssembler(packet)
		}
		t.transfers.Store(packet.ID, state)
	}

	// Retain a partial resumable stream across a dropped connection so a re-send
	// resumes; delete everything else (and completed streams) on return. Use the
	// stable transfer ID (packet is reassigned — and nil'd — in the loop below).
	transferID := state.ID
	defer func() {
		if sc.Resumable && sc.Streaming && !t.isTransferComplete(state) {
			return
		}
		t.transfers.Delete(transferID)
	}()

	// Acknowledge the init; for a resumable stream, report the resume point (the
	// next block index still needed) in ChunkNumber.
	ack := protocol.NewPacket(protocol.PacketTypeAcknowledgement, nil, "", packet.SourceNode)
	ack.SourceNode = t.selfID
	if sc.Resumable && state.stream != nil {
		ack.ChunkNumber = state.stream.resumeFrom()
	}
	ack.Sign(t.signKey)
	if err := protocol.WritePacket(conn, ack); err != nil {
		return
	}

	for {
		packet, err = protocol.ReadPacket(r)
		if err != nil {
			break // EOF or read error ends the stream
		}

		if err := t.processChunk(packet, state); err != nil {
			return
		}

		// Send chunk acknowledgment
		ack := protocol.NewPacket(protocol.PacketTypeAcknowledgement, nil, "", packet.SourceNode)
		ack.SourceNode = t.selfID
		ack.Sign(t.signKey)
		if err := protocol.WritePacket(conn, ack); err != nil {
			return
		}

		// For streaming transfers, keep draining and acking until the sender
		// closes: a block reconstructs from dataShards fragments, but the sender
		// is still transmitting that block's parity fragments and waiting for
		// their acks. Breaking early would deadlock it. The sink is already
		// flushed/closed by the assembler when the final block completes.
		if state.stream == nil && t.isTransferComplete(state) {
			break
		}
	}

	// Reassemble in memory and deliver to the caller.
	if t.isTransferComplete(state) {
		t.deliver(state)
	}
}

// schemeFromPacket extracts the fragmentation scheme advertised on a packet.
func schemeFromPacket(p *protocol.Packet) scheme {
	return scheme{
		DataShards:   p.DataShards,
		ParityShards: p.ParityShards,
		OriginalLen:  p.OriginalLen,
		Variable:     p.Variable,
		Streaming:    p.Streaming,
		HybridSealed: p.HybridSealed,
		PQ:           p.PQ,
		Resumable:    p.Resumable,
	}
}

// deliver reassembles the received chunks according to the transfer's scheme and
// dispatches the payload. It returns true if a payload was successfully
// reassembled and delivered.
func (t *Transfer) deliver(state *transferState) bool {
	// Streaming transfers are flushed block-by-block by the assembler as they
	// arrive; there is no whole-payload reassembly or dispatch here.
	if state.stream != nil {
		return t.isTransferComplete(state)
	}
	data, ok := t.reassemble(state)
	if !ok {
		return false
	}
	t.dispatch(state, data)
	return true
}

// dispatch hands the reassembled payload to the onData callback and sends an
// end-to-end acknowledgement back to the source. Both run in their own
// goroutines so a slow handler or unreachable source cannot block the caller.
func (t *Transfer) dispatch(state *transferState, data []byte) {
	t.metrics.IncDelivered()
	t.recordHop(HopDeliver, protocol.HexID(state.ID)[:8])
	if t.onData != nil {
		go t.onData(data, state.scheme.Variable)
	}
	// Prefer the anonymous reply block (forwarded transfers); fall back to the
	// source-addressed ack for direct, non-anonymous transfers.
	switch {
	case len(state.replyBlock) > 0:
		go t.sendAckReply(state.replyBlock)
	case state.sourceNode != "":
		go t.sendAck(state.sourceNode, state.ID)
	}
}

// applyScheme stamps the fragmentation scheme (RS metadata + variable flag) onto
// a packet so the receiver can reassemble the transfer.
func applyScheme(p *protocol.Packet, sc scheme) {
	p.DataShards = sc.DataShards
	p.ParityShards = sc.ParityShards
	p.OriginalLen = sc.OriginalLen
	p.Variable = sc.Variable
	p.Streaming = sc.Streaming
	p.HybridSealed = sc.HybridSealed
	p.PQ = sc.PQ
	p.Resumable = sc.Resumable
}

// sendToNode sends data to a specific node
func (t *Transfer) sendToNode(node *discovery.Node, id [32]byte, frags []fragment.Fragment, meta *storage.ChunkMeta, sc scheme) error {
	// Dial the node on the data port it advertised (node.Address carries the
	// discovery-port address, so the port there is not the data port).
	addr := peerDialAddr(node)

	var conn net.Conn
	var err error

	// Try to connect with retries
	for i := 0; i < maxRetries; i++ {
		conn, err = net.Dial("tcp", addr)
		if err == nil {
			break
		}
		time.Sleep(retryDelay)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to node %s: %w", node.ID, err)
	}
	defer conn.Close()

	r := bufio.NewReader(conn)

	// Send initial packet with metadata
	initPacket := protocol.NewPacket(protocol.PacketTypeData, nil, meta.DestGroup, meta.DestNode)
	initPacket.ID = id
	initPacket.TotalChunks = meta.TotalChunks
	initPacket.SourceNode = t.selfID
	applyScheme(initPacket, sc)
	initPacket.Sign(t.signKey)

	if err := protocol.WritePacket(conn, initPacket); err != nil {
		return fmt.Errorf("failed to send initial packet: %w", err)
	}

	// Wait for acknowledgment
	if _, err := protocol.ReadPacket(r); err != nil {
		return fmt.Errorf("failed to receive acknowledgment: %w", err)
	}

	// Send fragments (Index is 0-based; Payload may be sealed ciphertext). A large
	// fragment is split into transport-sized sub-chunks, each its own packet.
	for _, frag := range frags {
		if err := t.sendFragmentDirect(conn, r, id, meta, sc, frag); err != nil {
			return err
		}
	}

	return nil
}

// sendFragmentDirect writes one logical fragment (split into sub-chunks) over an
// open streamed connection, waiting for each per-chunk ack. Used by both the
// whole-payload direct path and the direct streaming path.
func (t *Transfer) sendFragmentDirect(conn net.Conn, r *bufio.Reader, id [32]byte, meta *storage.ChunkMeta, sc scheme, frag fragment.Fragment) error {
	for _, piece := range fragmentPieces(frag, t.subChunkSize) {
		packet := protocol.NewPacket(protocol.PacketTypeData, piece.Payload, meta.DestGroup, meta.DestNode)
		packet.ID = id
		packet.ChunkNumber = piece.Index
		packet.TotalChunks = piece.Total
		packet.SubIndex = piece.SubIndex
		packet.SubTotal = piece.SubTotal
		stampStreaming(packet, piece)
		packet.SourceNode = t.selfID
		applyScheme(packet, sc)
		packet.Sign(t.signKey)

		if err := protocol.WritePacket(conn, packet); err != nil {
			return fmt.Errorf("failed to send fragment %d sub-chunk %d: %w", piece.Index, piece.SubIndex, err)
		}

		// Wait for chunk acknowledgment
		if _, err := protocol.ReadPacket(r); err != nil {
			return fmt.Errorf("failed to receive fragment acknowledgment: %w", err)
		}
		t.metrics.IncSent()
		t.recordHop(HopSend, "direct")
	}
	return nil
}

// shouldAcceptTransfer determines if we should accept an incoming transfer
func (t *Transfer) shouldAcceptTransfer(packet *protocol.Packet) bool {
	return packet.DestNode == t.selfID ||
		packet.DestNode == "" &&
			(packet.DestGroup == "ANY" || packet.DestGroup == "ALL")
}

// processChunk handles an incoming chunk of data
func (t *Transfer) processChunk(packet *protocol.Packet, state *transferState) error {
	// Drop packets that fail integrity verification
	if !packet.Verify() {
		t.metrics.IncDropped()
		t.recordHop(HopDrop, "bad-signature")
		return fmt.Errorf("chunk %d failed signature verification", packet.ChunkNumber)
	}

	// Streaming transfers reassemble and flush per block, not into the whole-
	// payload buffer.
	if state.stream != nil {
		state.stream.add(packet)
		return nil
	}

	// Sub-chunks reassemble into the logical fragment before it is recorded.
	// Reassembly is driven from this in-memory copy (not storage) to avoid the
	// storage chunkNum==1 meta quirk; the receive-side SaveChunk is dropped.
	idx, payload, ok := absorbFragmentPieceLocked(state, packet)
	if ok {
		state.Chunks[idx] = payload
		state.Received[idx] = true
	}
	return nil
}

// isTransferComplete checks if all chunks have been received
func (t *Transfer) isTransferComplete(state *transferState) bool {
	if state.stream != nil {
		state.stream.mu.Lock()
		defer state.stream.mu.Unlock()
		return state.stream.done
	}
	return isCompleteLocked(state)
}

// isCompleteLocked reports whether all 0-based indices are present. Callers on
// the concurrent forwarded path must hold state.mu; the single-goroutine
// streamed path may call it directly.
func isCompleteLocked(state *transferState) bool {
	if uint32(len(state.Received)) != state.Total {
		return false
	}
	for i := uint32(0); i < state.Total; i++ {
		if !state.Received[i] {
			return false
		}
	}
	return true
}

// buildFragments produces the wire fragments for data together with the scheme
// the receiver needs to reassemble them. When erasure coding is configured (and
// the payload is large enough) it Reed-Solomon-encodes into data+parity shards;
// otherwise it falls back to sealed (or plain) sequential chunking.
func (t *Transfer) buildFragments(id [32]byte, data []byte, variable bool, sealer encryption.Sealer) ([]fragment.Fragment, scheme, error) {
	sc := scheme{Variable: variable}

	// Erasure-coded path (requires a sealer and enough data to split).
	if sealer != nil && t.dataShards > 0 && t.parityShards > 0 && len(data) >= t.dataShards {
		f, err := fragment.NewRSFragmenter(sealer, t.dataShards, t.parityShards)
		if err == nil {
			frags, origLen, err := f.Fragment(id, data)
			if err == nil {
				sc.DataShards = uint32(t.dataShards)
				sc.ParityShards = uint32(t.parityShards)
				sc.OriginalLen = uint64(origLen)
				return frags, sc, nil
			}
		}
		// Fall through to sequential chunking on any RS setup failure.
	}

	// Sealed sequential chunking.
	if sealer != nil {
		f, err := fragment.NewFragmenter(sealer, maxChunkSize)
		if err != nil {
			return nil, sc, err
		}
		frags, err := f.Fragment(id, data)
		return frags, sc, err
	}

	// Plaintext sequential chunking (no key configured).
	chunks := fragment.Split(data, maxChunkSize)
	total := uint32(len(chunks))
	frags := make([]fragment.Fragment, len(chunks))
	for i := range chunks {
		frags[i] = fragment.Fragment{
			TransferID: id,
			Index:      uint32(i),
			Total:      total,
			Payload:    chunks[i],
		}
	}
	return frags, sc, nil
}

// fragmentPieces splits one logical fragment into transport-sized wire pieces.
// A fragment that already fits in a single packet yields one piece with
// SubTotal == 1. Larger fragments (typically big Reed-Solomon shards) are split
// into ceil(len/subChunkSize) pieces that share the fragment's Index and Total
// and carry SubIndex/SubTotal so the receiver can reassemble them before the
// fragment enters reassembly. A non-positive size disables splitting.
func fragmentPieces(frag fragment.Fragment, subChunkSize int) []fragment.Fragment {
	if subChunkSize <= 0 || len(frag.Payload) <= subChunkSize {
		f := frag
		f.SubIndex = 0
		f.SubTotal = 1
		return []fragment.Fragment{f}
	}
	parts := fragment.Split(frag.Payload, subChunkSize)
	out := make([]fragment.Fragment, len(parts))
	for i, p := range parts {
		f := frag // copy logical + streaming metadata (BlockIndex/BlockLen/Final/Streaming)
		f.SubIndex = uint32(i)
		f.SubTotal = uint32(len(parts))
		f.Payload = p
		out[i] = f
	}
	return out
}

// reassemble rebuilds the original payload from a transfer's received chunks
// according to its scheme (Reed-Solomon or sequential). It returns the payload
// and true on success, or false if reassembly is not yet possible or failed.
func (t *Transfer) reassemble(state *transferState) ([]byte, bool) {
	// Per-recipient sealed transfers are opened with this node's private key(s);
	// otherwise the shared-key sealer.
	sealer := t.recipientOpener(state.scheme)

	if state.scheme.DataShards > 0 {
		r := fragment.NewRSReassembler(sealer, int(state.scheme.DataShards), int(state.scheme.ParityShards), int(state.scheme.OriginalLen))
		for idx, payload := range state.Chunks {
			_ = r.Add(fragment.Fragment{TransferID: state.ID, Index: idx, Total: state.Total, Payload: payload})
		}
		data, err := r.Reconstruct(state.ID)
		if err != nil {
			return nil, false
		}
		return data, true
	}

	data, err := reassembleChunks(sealer, state.ID, state.Total, state.Chunks)
	if err != nil {
		return nil, false
	}
	return data, true
}

// reassembleChunks rebuilds the original payload from the received 0-based
// chunks. With a sealer set each chunk is opened via a Reassembler (with the
// position-binding aad); otherwise the chunks are joined in index order.
func reassembleChunks(sealer encryption.Sealer, id [32]byte, total uint32, chunks map[uint32][]byte) ([]byte, error) {
	if sealer != nil {
		r := fragment.NewReassembler(sealer, total)
		for i := uint32(0); i < total; i++ {
			if err := r.Add(fragment.Fragment{
				TransferID: id,
				Index:      i,
				Total:      total,
				Payload:    chunks[i],
			}); err != nil {
				return nil, err
			}
		}
		return r.Assemble(id)
	}

	ordered := make([][]byte, total)
	for i := uint32(0); i < total; i++ {
		ordered[i] = chunks[i]
	}
	return fragment.Join(ordered), nil
}

// nodesToPeers adapts discovery nodes into routing peers so the routing package
// stays decoupled from discovery.
func nodesToPeers(nodes []*discovery.Node) []routing.Peer {
	peers := make([]routing.Peer, 0, len(nodes))
	for _, n := range nodes {
		peers = append(peers, routing.Peer{
			ID:           n.ID,
			Address:      n.Address,
			Latency:      n.Latency,
			Active:       n.Active,
			PubKey:       n.PubKey,
			Port:         n.Port,
			RelayCapable: hasCapability(n.Capabilities, "relay"),
		})
	}
	return peers
}

// hasCapability reports whether caps contains want.
func hasCapability(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

// sendForwarded routes each fragment to dest through hopCount intermediary hops.
// Each fragment is wrapped in per-hop layers (via encryption.BuildOnion) so a
// relay learns only its next hop, never the payload or both endpoints. Fragments
// are entered through rotating first hops for path diversity. It returns an error
// if a route cannot be built or keys are missing, so the caller can fall back to
// a direct send.
func (t *Transfer) sendForwarded(dest *discovery.Node, nodes []*discovery.Node, id [32]byte, frags []fragment.Fragment, sc scheme, ackToken []byte) error {
	fc, err := t.newForwardCtx(dest, nodes, id, sc, ackToken)
	if err != nil {
		return err
	}
	for _, frag := range frags {
		if err := fc.sendFragment(frag); err != nil {
			return err
		}
	}
	return nil
}

// forwardCtx holds the route/reply-block context for one forwarded transfer so
// fragments can be emitted one at a time (used by both the whole-payload path
// and the streaming path, which builds fragments block by block).
type forwardCtx struct {
	t          *Transfer
	id         [32]byte
	sc         scheme
	destID     string
	destPeer   routing.Peer
	relays     []routing.Peer
	planner    *routing.Planner
	replyBlock []byte
	paths      int
}

// newForwardCtx builds the reusable forwarding context: eligible relays, the
// destination peer, a single-use anonymous reply block, and the redundancy path
// count. Errors if forwarding is unavailable (missing keys).
func (t *Transfer) newForwardCtx(dest *discovery.Node, nodes []*discovery.Node, id [32]byte, sc scheme, ackToken []byte) (*forwardCtx, error) {
	if t.nodePriv == nil || len(dest.PubKey) == 0 {
		return nil, fmt.Errorf("forwarding unavailable: missing keys")
	}

	// Eligible intermediaries: active, relay-capable, keyed, not the dest, and
	// not excommunicated. Address is the node's dial-able data address.
	relays := t.relayPeers(nodes, dest.ID)

	// If the destination is reachable only through a circuit relay it reserved
	// with, force the path to end at that relay so the final hop is delivered
	// over the reservation rather than dialed.
	if len(dest.RelayIDs) > 0 {
		if rr := pickReservationRelay(relays, dest.RelayIDs); rr != nil {
			relays = []routing.Peer{*rr}
		}
	}

	// Number of independent paths per fragment. Capped at the number of distinct
	// intermediaries so extra copies don't just repeat the same first hop.
	paths := t.redundancy
	if paths < 1 {
		paths = 1
	}
	if len(relays) > 0 && paths > len(relays) {
		paths = len(relays)
	}

	return &forwardCtx{
		t:          t,
		id:         id,
		sc:         sc,
		destID:     dest.ID,
		destPeer:   routing.Peer{ID: dest.ID, Address: peerDialAddr(dest), PubKey: dest.PubKey, Active: true},
		relays:     relays,
		planner:    &routing.Planner{},
		replyBlock: t.buildReplyBlock(id, relays, ackToken),
		paths:      paths,
	}, nil
}

// sendFragment emits one logical fragment: it is split into transport sub-chunks,
// and each sub-chunk is sent over `paths` independent onion routes. Every
// sub-chunk must reach at least one first hop or the fragment fails.
func (fc *forwardCtx) sendFragment(frag fragment.Fragment) error {
	t := fc.t
	for _, piece := range fragmentPieces(frag, t.subChunkSize) {
		inner, err := t.buildInnerFragment(fc.id, fc.destID, piece, fc.sc, fc.replyBlock)
		if err != nil {
			return err
		}

		// Send the sub-chunk over `paths` independent routes. Each copy rotates
		// the intermediary order so it enters through a different first hop; the
		// receiver deduplicates by (block, fragment, sub-chunk) index, so any one
		// arriving copy suffices.
		sent := false
		for copyIdx := 0; copyIdx < fc.paths; copyIdx++ {
			seed := int(piece.BlockIndex) + int(piece.Index) + int(piece.SubIndex) + copyIdx
			hops, err := fc.planner.BuildPath(fc.destPeer, rotatePeers(fc.relays, seed), t.hopCount)
			if err != nil {
				return err
			}
			onionHops, err := toOnionHops(hops)
			if err != nil {
				return err
			}
			blob, err := encryption.BuildOnion(onionHops, inner)
			if err != nil {
				return err
			}
			if err := t.sendRelayBlob(hops[0].Address, blob); err == nil {
				sent = true
			}
		}
		if !sent {
			return fmt.Errorf("block %d fragment %d sub-chunk %d/%d: all %d paths failed", piece.BlockIndex, piece.Index, piece.SubIndex, piece.SubTotal, fc.paths)
		}
		t.metrics.IncSent()
		t.recordHop(HopSend, "forwarded")
	}
	return nil
}

// rotatePeers returns peers rotated left by n (mod len), leaving the input
// slice untouched.
func rotatePeers(peers []routing.Peer, n int) []routing.Peer {
	if len(peers) == 0 {
		return peers
	}
	n = ((n % len(peers)) + len(peers)) % len(peers)
	out := make([]routing.Peer, 0, len(peers))
	out = append(out, peers[n:]...)
	out = append(out, peers[:n]...)
	return out
}

// toOnionHops converts routing hops into encryption hops, parsing each hop's
// raw X25519 public key.
func toOnionHops(hops []routing.Hop) ([]encryption.OnionHop, error) {
	out := make([]encryption.OnionHop, 0, len(hops))
	for _, h := range hops {
		pub, err := ecdh.X25519().NewPublicKey(h.PubKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key for hop %s: %w", h.NodeID, err)
		}
		out = append(out, encryption.OnionHop{NodeID: h.NodeID, Addr: h.Address, PubKey: pub})
	}
	return out, nil
}

// buildInnerFragment builds the marshaled data packet the final recipient
// receives after peeling the last onion layer. It is deliberately anonymous: no
// SourceNode and no identity signature, so the destination cannot learn who sent
// it. Authenticity of the bytes comes from the onion's final-layer AEAD, and of
// the content from the developer-key AEAD on the fragment payload. A single-use
// reply block lets the destination acknowledge delivery without learning the
// sender.
func (t *Transfer) buildInnerFragment(id [32]byte, destID string, frag fragment.Fragment, sc scheme, replyBlock []byte) ([]byte, error) {
	pkt := protocol.NewPacket(protocol.PacketTypeData, frag.Payload, "", destID)
	pkt.ID = id
	pkt.ChunkNumber = frag.Index
	pkt.TotalChunks = frag.Total
	pkt.SubIndex = frag.SubIndex
	pkt.SubTotal = frag.SubTotal
	stampStreaming(pkt, frag)
	pkt.ReplyBlock = replyBlock
	applyScheme(pkt, sc)
	t.padPacket(pkt)
	return pkt.MarshalBinary()
}

// sendRelayBlob sends a one-shot relay packet carrying the wrapped blob to addr
// (a host:dataPort address), reusing a pooled connection when available.
func (t *Transfer) sendRelayBlob(addr string, blob []byte) error {
	t.applyJitter()
	pkt := protocol.NewPacket(protocol.PacketTypeRelay, blob, "", "")
	pkt.SourceNode = t.selfID
	pkt.Sign(t.signKey)
	return t.sendPooled(addr, pkt)
}

// handleRelay peels one layer of a forwarded packet with this node's private key
// and either delivers it (final recipient) or forwards it to the next hop.
func (t *Transfer) handleRelay(pkt *protocol.Packet) {
	if t.nodePriv == nil {
		return
	}
	t.metrics.IncReceived()
	t.recordHop(HopReceive, "")
	peel, err := encryption.PeelOnion(t.nodePriv, pkt.Payload)
	if err != nil {
		t.metrics.IncDropped()
		t.recordHop(HopDrop, "unpeelable")
		return // not addressed to us, or corrupt
	}

	if peel.IsFinal {
		var inner protocol.Packet
		if err := inner.UnmarshalBinary(peel.Inner); err != nil {
			t.metrics.IncDropped()
			t.recordHop(HopDrop, "malformed-inner")
			return
		}
		// The inner bytes were just authenticated by the onion's final-layer
		// AEAD (PeelOnion), so no identity signature is required — and omitting
		// one is what keeps the sender anonymous to the destination. Content
		// authenticity comes from the developer-key AEAD on the fragment payload.

		// Cover traffic: a decoy is routed exactly like real traffic but silently
		// dropped here, so observers cannot tell real transfers from noise.
		if inner.Decoy {
			t.metrics.IncDecoy()
			t.recordHop(HopDecoy, "")
			return
		}

		// A forwarded acknowledgement is either our own relay-liveness probe
		// coming home (proving the relay forwarded it) or a transfer delivery
		// ack. Probes are matched first by their unforgeable ID.
		if inner.Type == protocol.PacketTypeAcknowledgement {
			if t.signalProbe(inner.ID) {
				return
			}
			t.signalAckToken(inner.ID, inner.Payload)
			return
		}
		t.ingestForwardedFragment(&inner)
		return
	}

	// Forward the inner blob one hop onward (best-effort). If the next hop is a
	// node that reserved through us (behind NAT), deliver over its held circuit
	// connection instead of dialing its unreachable address.
	t.forwardToNextHop(peel.NextNode, peel.NextAddr, peel.Inner)
}

// ingestForwardedFragment accumulates a fragment that arrived via forwarding and
// delivers the payload once all fragments for the transfer are present. Fragments
// for one transfer may arrive concurrently over separate connections, so state is
// guarded by its mutex.
func (t *Transfer) ingestForwardedFragment(pkt *protocol.Packet) {
	v, _ := t.transfers.LoadOrStore(pkt.ID, &transferState{
		ID:          pkt.ID,
		Total:       pkt.TotalChunks,
		TotalChunks: pkt.TotalChunks,
		Received:    make(map[uint32]bool),
		Chunks:      make(map[uint32][]byte),
		scheme:      schemeFromPacket(pkt),
		sourceNode:  pkt.SourceNode,
		replyBlock:  pkt.ReplyBlock,
		StartTime:   time.Now(),
	})
	state := v.(*transferState)

	// Streaming transfers reassemble and flush per block via the assembler
	// (created lazily on the first streamed fragment).
	if pkt.Streaming {
		state.mu.Lock()
		if state.stream == nil {
			state.stream = t.newStreamAssembler(pkt)
		}
		sa := state.stream
		state.mu.Unlock()
		if sa.add(pkt) {
			t.transfers.Delete(pkt.ID)
		}
		return
	}

	state.mu.Lock()
	if state.delivered {
		state.mu.Unlock()
		return
	}
	// Sub-chunks of a large shard reassemble into the logical fragment first.
	if idx, payload, ok := absorbFragmentPieceLocked(state, pkt); ok {
		state.Chunks[idx] = payload
		state.Received[idx] = true
	}
	// Attempt reassembly once enough fragments/shards are present. For erasure
	// coding this is dataShards; for sequential it is all indices. reassemble
	// may still fail (e.g. an RS shard was corrupt), in which case we stay
	// undelivered and wait for more.
	var data []byte
	delivered := false
	if enoughToReassembleLocked(state) {
		if d, ok := t.reassemble(state); ok {
			data = d
			state.delivered = true
			delivered = true
		}
	}
	state.mu.Unlock()

	if delivered {
		t.dispatch(state, data)
		t.transfers.Delete(pkt.ID)
	}
}

// absorbFragmentPieceLocked records one wire packet, transparently reassembling
// sub-chunks. It returns the fragment's logical index and complete (possibly
// sealed) payload once every sub-chunk for that index has arrived; ok is false
// while pieces are still missing (or the piece was a duplicate). A packet with
// SubTotal <= 1 carries a whole fragment and completes immediately. Callers must
// hold state.mu.
func absorbFragmentPieceLocked(state *transferState, pkt *protocol.Packet) (idx uint32, payload []byte, ok bool) {
	if state.subParts == nil {
		state.subParts = make(map[uint32]map[uint32][]byte)
	}
	return absorbSubChunk(state.Received, state.subParts, pkt)
}

// absorbSubChunk records one wire packet into the given per-fragment buffers,
// transparently reassembling sub-chunks. It returns the fragment's logical index
// and complete (possibly sealed) payload once every sub-chunk for that index has
// arrived; ok is false while pieces are still missing, on a duplicate, or on an
// out-of-range sub-chunk index. A packet with SubTotal <= 1 carries a whole
// fragment and completes immediately. received marks already-complete indices
// (for the duplicate check); subParts must be non-nil (it may be empty). Shared
// by the whole-payload receive paths and the streaming per-block assembler.
func absorbSubChunk(received map[uint32]bool, subParts map[uint32]map[uint32][]byte, pkt *protocol.Packet) (idx uint32, payload []byte, ok bool) {
	idx = pkt.ChunkNumber
	if received[idx] {
		return idx, nil, false // already have the whole fragment
	}
	if pkt.SubTotal <= 1 {
		return idx, append([]byte(nil), pkt.Payload...), true
	}
	if pkt.SubIndex >= pkt.SubTotal {
		return idx, nil, false // out-of-range sub-chunk index
	}

	parts := subParts[idx]
	if parts == nil {
		parts = make(map[uint32][]byte)
		subParts[idx] = parts
	}
	if _, dup := parts[pkt.SubIndex]; !dup {
		parts[pkt.SubIndex] = append([]byte(nil), pkt.Payload...)
	}
	if uint32(len(parts)) < pkt.SubTotal {
		return idx, nil, false // still missing sub-chunks
	}

	// All sub-chunks present: concatenate in order and release the buffer.
	buf := make([]byte, 0)
	for i := uint32(0); i < pkt.SubTotal; i++ {
		buf = append(buf, parts[i]...)
	}
	delete(subParts, idx)
	return idx, buf, true
}

// enoughToReassembleLocked reports whether enough fragments have arrived to try
// reassembly. Callers must hold state.mu. For Reed-Solomon this is DataShards
// shards; for sequential chunking it is every index.
func enoughToReassembleLocked(state *transferState) bool {
	if state.scheme.DataShards > 0 {
		return uint32(len(state.Received)) >= state.scheme.DataShards
	}
	return isCompleteLocked(state)
}

// pendingAck holds the state a sender waits on for a confirmed transfer. The ack
// is only accepted if it proves it came from the intended destination: a direct
// ack must be signed by destKey; a forwarded (anonymous) ack must echo the secret
// token. This prevents a transfer-ID-knowing attacker from forging an ack to stop
// the sender's resends.
type pendingAck struct {
	ch      chan struct{}
	destKey []byte // expected destination Ed25519 key (direct acks)
	token   []byte // secret echoed by the anonymous reply-block ack
}

// registerAck registers a pending confirmed transfer keyed by id.
func (t *Transfer) registerAck(id [32]byte, destKey, token []byte) chan struct{} {
	ch := make(chan struct{})
	t.ackMu.Lock()
	t.pendingAcks[id] = &pendingAck{ch: ch, destKey: destKey, token: token}
	t.ackMu.Unlock()
	return ch
}

// unregisterAck removes any pending ack registration for id.
func (t *Transfer) unregisterAck(id [32]byte) {
	t.ackMu.Lock()
	delete(t.pendingAcks, id)
	t.ackMu.Unlock()
}

// resolveAck closes the pending channel for id iff accept(pending) is true,
// authenticating the ack before it can stop the sender's resends.
func (t *Transfer) resolveAck(id [32]byte, accept func(*pendingAck) bool) {
	t.ackMu.Lock()
	pa, ok := t.pendingAcks[id]
	if ok && accept(pa) {
		delete(t.pendingAcks, id)
	} else {
		ok = false
	}
	t.ackMu.Unlock()
	if ok {
		t.metrics.IncAck()
		close(pa.ch)
	}
}

// signalAckFrom accepts a direct ack only if it was signed by the expected
// destination's key.
func (t *Transfer) signalAckFrom(id [32]byte, signerKey []byte) {
	t.resolveAck(id, func(pa *pendingAck) bool {
		return len(pa.destKey) > 0 && subtle.ConstantTimeCompare(pa.destKey, signerKey) == 1
	})
}

// signalAckToken accepts a forwarded (anonymous) reply-block ack only if it
// echoes the transfer's secret token.
func (t *Transfer) signalAckToken(id [32]byte, token []byte) {
	t.resolveAck(id, func(pa *pendingAck) bool {
		return len(pa.token) > 0 && subtle.ConstantTimeCompare(pa.token, token) == 1
	})
}

// randomToken returns a fresh 16-byte secret for authenticating an anonymous ack.
func randomToken() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	return b
}

// sendAck sends a direct, identity-signed delivery acknowledgement for transfer
// id back to its source. Used only for direct (non-anonymous) transfers, where
// both ends already know each other; the receiver binds it to this node's key.
func (t *Transfer) sendAck(sourceID string, id [32]byte) {
	if sourceID == "" || sourceID == t.selfID || t.discovery == nil {
		return
	}
	var src *discovery.Node
	for _, n := range t.discovery.GetActiveNodes() {
		if n.ID == sourceID {
			src = n
			break
		}
	}
	if src == nil {
		return
	}

	ack := protocol.NewPacket(protocol.PacketTypeAcknowledgement, nil, "", sourceID)
	ack.ID = id
	ack.SourceNode = t.selfID
	ack.Sign(t.signKey)
	_ = t.sendPooled(peerDialAddr(src), ack)
}

// dialWithRetries dials addr with the standard retry/backoff, returning nil on
// failure.
func dialWithRetries(addr string) net.Conn {
	var conn net.Conn
	var err error
	for i := 0; i < maxRetries; i++ {
		conn, err = net.Dial("tcp", addr)
		if err == nil {
			return conn
		}
		time.Sleep(retryDelay)
	}
	return nil
}

// replyBlock is a single-use anonymous return path: an onion blob that routes
// back to the original sender, plus the entry relay address at which to inject
// it. The destination uses it to acknowledge delivery without ever learning the
// sender's identity or address.
type replyBlock struct {
	EntryAddr string
	Blob      []byte
}

// buildReplyBlock pre-builds an anonymous onion return path back to this node for
// acknowledging transfer id. The path runs through hopCount relays and
// terminates at this node, so the destination only ever learns the entry relay's
// address. Returns nil if no return path with at least one relay can be built
// (a zero-relay path would expose this node's address to the destination).
func (t *Transfer) buildReplyBlock(id [32]byte, relays []routing.Peer, ackToken []byte) []byte {
	if t.nodePriv == nil || t.hopCount < 1 || len(relays) == 0 {
		return nil
	}
	selfPeer := routing.Peer{
		ID:      t.selfID,
		Address: net.JoinHostPort(t.reachableHost(), strconv.Itoa(t.dataPort)),
		PubKey:  t.nodePriv.PublicKey().Bytes(),
		Active:  true,
	}
	hops, err := (&routing.Planner{}).BuildPath(selfPeer, relays, t.hopCount)
	if err != nil || len(hops) < 2 {
		return nil // need at least one relay before us
	}
	onionHops, err := toOnionHops(hops)
	if err != nil {
		return nil
	}
	// The innermost payload is an anonymous ack packet for this transfer,
	// carrying the secret token (in Payload) that authenticates it back to us.
	// The token is sealed to our own key, so a forger who lacks it cannot fake
	// an ack that we would accept. The sender peels the final layer and signals
	// its waiting SendData.
	ack := protocol.NewPacket(protocol.PacketTypeAcknowledgement, ackToken, "", "")
	ack.ID = id
	ackBytes, err := ack.MarshalBinary()
	if err != nil {
		return nil
	}
	blob, err := encryption.BuildOnion(onionHops, ackBytes)
	if err != nil {
		return nil
	}
	rb, err := json.Marshal(replyBlock{EntryAddr: hops[0].Address, Blob: blob})
	if err != nil {
		return nil
	}
	return rb
}

// sendAckReply injects a destination's acknowledgement into an anonymous reply
// block by sending the pre-built onion blob to its entry relay, which forwards
// it back to the original sender. The sender never learns the destination
// beyond the entry relay observing an ack in transit.
func (t *Transfer) sendAckReply(rbBytes []byte) {
	var rb replyBlock
	if err := json.Unmarshal(rbBytes, &rb); err != nil || rb.EntryAddr == "" {
		return
	}
	_ = t.sendRelayBlob(rb.EntryAddr, rb.Blob)
}

// selfDialHost best-effort determines this node's own reachable host for
// inclusion in reply paths, using the OS routing table without sending a packet.
// Falls back to loopback (correct for same-host tests; real cross-NAT
// reachability is a later roadmap item).
func selfDialHost() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return "127.0.0.1"
}
