package swarmsync

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/APoniatowski/syncswarm/internal/discovery"
	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/link"
	"github.com/APoniatowski/syncswarm/internal/monitoring"
	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/storage"
	"github.com/APoniatowski/syncswarm/internal/transfer"
)

// DefaultSeeds are the baked-in rendezvous addresses a node falls back to when no
// BootstrapPeers are configured (and DisableDefaultSeeds is not set), so an app
// can join the network with zero configuration. Use DNS names (not raw IPs) so the
// underlying hosts can rotate; list several, run by independent operators, so no
// single seed is load-bearing — that is what makes the network progressively
// decentralized. Applications may append their own.
var DefaultSeeds = []string{
	"seed.postal-studios.com:64512",
}

// MinBridgePSKLen is the shortest BridgePSK that offers meaningful resistance;
// below it, the HMAC the handshake exposes falls to an offline search from a
// single captured handshake.
const MinBridgePSKLen = 16

// Sentinel errors for send outcomes. Use errors.Is to branch on them rather than
// matching error text.
//
// The line that matters for an application is whether anything left the device:
//
//	err := node.SendTo(payload, peerID)
//	switch {
//	case errors.Is(err, swarmsync.ErrDestinationUnreachable),
//	     errors.Is(err, swarmsync.ErrNoAnonymousRoute):
//	    // Nothing was sent. Re-sending is correct.
//	case errors.Is(err, swarmsync.ErrNotConfirmed):
//	    // Fragments went out; no ack arrived. A store-and-forward relay may still
//	    // be holding them, so re-sending risks a duplicate. Prefer waiting for
//	    // OnDeliveryConfirmed, which fires if the ack lands later.
//	}
var (
	// ErrDestinationUnreachable is returned before anything is sent: the peer is
	// neither active nor reachable through a live circuit reservation.
	ErrDestinationUnreachable = transfer.ErrDestinationUnreachable

	// ErrNoAnonymousRoute is returned before anything is sent: StrictAnonymity is
	// set and no relay path with the required diversity exists.
	ErrNoAnonymousRoute = transfer.ErrNoAnonymousRoute

	// ErrNotConfirmed means fragments were sent but no end-to-end acknowledgement
	// arrived within the attempt budget. It does not mean the message failed to
	// arrive — see OnDeliveryConfirmed.
	ErrNotConfirmed = transfer.ErrNotConfirmed
)

// DefaultBridges are the baked-in bridge listeners a node can dial when it wants
// a bridge but has no particular transport node in mind — the convenience
// counterpart to DefaultSeeds, pointing at the same operators' bridge ports
// (64514) rather than their discovery ports (64512).
//
// Deliberately NOT applied unless a caller asks for a bridge: a bridge is a
// standing TCP connection, so defaulting every node to one would make these hosts
// permanent load-bearing infrastructure — exactly what DECENTRALIZED_BOOTSTRAP.md
// aims to avoid. Bootstrap is a brief exchange you stop needing once peers are
// cached; a bridge is not. Applications should append their own, and prefer a
// bridge on a host they or a peer operates.
var DefaultBridges = []string{
	"seed.postal-studios.com:64514",
}

// resolveSeedHosts returns the set of hosts (the seed names plus their resolved
// IPs) so onion path selection can recognise and deprioritize seed relays.
func resolveSeedHosts(seeds []string) map[string]bool {
	hosts := make(map[string]bool)
	for _, s := range seeds {
		host := s
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		hosts[host] = true
		if ips, err := net.LookupHost(host); err == nil {
			for _, ip := range ips {
				hosts[ip] = true
			}
		}
	}
	return hosts
}

// Options configures the SyncSwarm instance
type Options struct {
	// Directory where data will be stored (also holds the persistent identity key)
	StorageDir string
	// NodeID is DEPRECATED and ignored: a node's identity is now derived from its
	// Ed25519 public key and is available via SyncSwarm.NodeID(). Address peers by
	// that key-bound ID, which cannot be spoofed.
	NodeID string
	// Optional group this node belongs to
	Group string
	// Handler for receiving data
	OnDataReceived func([]byte)
	// Handler for receiving variables
	OnVariableReceived func(interface{})
	// Key is an optional 32-byte AES-256 key. When set, every fragment is
	// sealed before it leaves this node so relays and interceptors see only
	// ciphertext. Leave nil for the plaintext transport.
	Key []byte
	// BootstrapPeers are host:port UDP addresses of known nodes to contact on
	// startup, so this node can join a swarm beyond its local broadcast domain.
	BootstrapPeers []string
	// DisableDefaultSeeds opts out of the baked-in DefaultSeeds. By default a node
	// with no BootstrapPeers still tries the default seed(s) so it can join with
	// zero configuration; set this to rely solely on BootstrapPeers.
	DisableDefaultSeeds bool
	// BridgePeers are host:port TCP addresses of known transport nodes to open a
	// persistent bridge to. Announces and path requests fan out across bridges, so
	// this node discovers (and is discovered by) peers on networks its UDP
	// broadcast cannot reach — the connection-agnostic way to cross subnets/the
	// internet without DNS. Each entry must be a reachable node running a TCP
	// server interface. Unreachable bridges are skipped (logged), not fatal.
	BridgePeers []string
	// BridgeListen, if set (e.g. ":64513"), makes this node accept inbound TCP
	// bridges from other nodes — the role a reachable transport node plays so
	// clients behind NAT can bridge discovery through it. Empty means no listener.
	BridgeListen string
	// BridgePSK, when set, is a pre-shared key that gates who may attach a TCP
	// bridge — both inbound (BridgeListen) and outbound (BridgePeers). Peers
	// without the key cannot attach in either direction, and the check is mutual,
	// so a client also proves it reached the intended bridge.
	//
	// Leave empty for a public bridge: the default is open, which is what a seed
	// node wants. Set it for a private deployment, where a bridge host would
	// otherwise see the discovery metadata of everyone attached to it and be able
	// to drop their traffic selectively.
	//
	// This is access control, not confidentiality — discovery packets are signed
	// and payloads are sealed end to end regardless.
	//
	// Use at least 16 bytes: the handshake exposes an HMAC over known values, so a
	// short key can be recovered offline from a single captured handshake. A
	// shorter one is accepted but logged as a warning. Never source it from a
	// command-line argument — a process's command line is readable by every local
	// user via ps.
	BridgePSK []byte
	// OnDeliveryConfirmed, when set, fires if a delivery acknowledgement arrives
	// *after* the send already returned ErrNotConfirmed. That happens when the
	// recipient was offline: a store-and-forward relay holds the fragments,
	// redelivers when they return, and the ack follows — long after SendTo gave up.
	//
	// Without this the sender is left permanently wrong about a message that did
	// arrive, and no amount of application logic can correct it. Use SendToTracked
	// to learn the transfer ID at send time so the callback can be matched to a
	// message.
	//
	// Called on a background goroutine; keep it quick and do not call back into
	// the node from it. Best-effort: it fires within roughly 30 minutes of the
	// send, and not at all if the node restarts (the registration is in memory).
	OnDeliveryConfirmed func(id [32]byte, destNode string)
	// AutoInterface enables zero-configuration LAN discovery: the node joins an
	// IPv6 link-local multicast group and finds other SyncSwarm nodes on the same
	// physical network with no bootstrap host, DNS seed, or broadcast-address
	// config — plugging two machines into the same switch/Wi-Fi is enough. It is
	// additive (composes with seeds, bridges, and UDP broadcast); a host with no
	// multicast-capable interface simply gets no LAN peering (logged, not fatal).
	AutoInterface bool
	// LoRaDevice, if set (e.g. "/dev/ttyUSB0"), opens a serial-attached LoRa modem
	// (Reticulum RNode / Meshtastic / MeshCore in KISS mode) and joins the mesh
	// over the air — no IP required. Announces/path-requests flood over it like any
	// broadcast medium. LoRaBaud 0 uses a sensible default. A device that can't be
	// opened is logged, not fatal. Serial backends exist for Linux and macOS; on
	// other platforms a networked RNode over TCP is reachable via a custom interface.
	LoRaDevice string
	LoRaBaud   int
	// SerialDevice / SerialBaud do the same for a generic KISS/serial radio modem
	// (TNC, packet radio).
	SerialDevice string
	SerialBaud   int
	// LoRaDutyCycle / SerialDutyCycle limit transmissions to that fraction of wall
	// time on air (e.g. 0.01 for the 1% that licence-free sub-GHz bands such as EU
	// 868 MHz commonly permit), averaged over an hour. Exceeding the limit is both
	// illegal in those bands and antisocial on a shared channel, so sends over
	// budget are refused with a back-pressure error rather than transmitted. 0
	// disables the limit (the default, appropriate for licensed or wired links).
	LoRaDutyCycle   float64
	SerialDutyCycle float64
	// ReliableLinkTransfer routes node-addressed SendTo/SendToAsync through the
	// Resource-over-Link path (SendToResource) instead of the TCP transfer: reliable
	// (selective-ARQ) delivery over any interface a Link reaches — a TCP bridge, a
	// LAN-multicast peer, or a LoRa link — not just where a direct TCP dial works.
	// Off by default (the TCP/onion transfer stays the default path); onion routing
	// is unaffected — this only changes the direct node-addressed case. Phase 0b.2.
	ReliableLinkTransfer bool
	// OnionOverLinks carries onion-routed (forwarded) traffic over encrypted Links
	// instead of direct TCP dials between hops, so anonymous transfers reach hops
	// that are only reachable via a bridge or radio, and each hop is
	// initiator-anonymous (the Link handshake carries no initiator identity). The
	// source-routed onion and anonymous reply-block ack are unchanged. Off by default
	// (TCP stays the default onion transport, Links a fallback). Phase 0b.3.
	OnionOverLinks bool
	// PerHopRouting sends targeted transfers via per-hop transport routing
	// (Reticulum-style: transport nodes forward toward the destination using their
	// announce path tables) instead of source-routed onion — more efficient and
	// resilient, and it reaches destinations across bridges/radio via the path table.
	// For the NON-anonymous profiles only: it is ignored under anonymity
	// (StrictAnonymity / adaptive onion), so ProfileAnonymous always keeps onion
	// source-routing. Falls back to onion/direct when no path is known. Off by
	// default. Phase 3.
	PerHopRouting bool
	// HopCount is the number of intermediary hops each fragment is routed
	// through toward a specific destination (SendTo). 0 means direct delivery.
	// Requires enough relay-capable peers to be discovered; otherwise the node
	// falls back to a direct send.
	HopCount int
	// Relay advertises this node as willing to forward traffic for others,
	// letting it serve as an intermediary hop in other nodes' paths.
	Relay bool
	// NeedsRelay marks this node as unable to accept inbound connections (e.g.
	// behind NAT). It holds persistent circuit reservations with reachable
	// relays, which forward its inbound traffic back over the held connection,
	// and advertises those relays so peers can route to it through them.
	NeedsRelay bool
	// SealToRecipient enables per-recipient end-to-end content sealing: a targeted
	// SendTo to a keyed node seals fragments to that node's public key instead of
	// (or in addition to) the shared Key, so only that recipient can open them —
	// no shared secret required, and the app doesn't have to build its own
	// encryption layer. Only the sender sets this; the receiver opens with its
	// node key automatically. Applies to targeted SendTo and SendStream (not
	// broadcasts). SendStream still needs DataShards/ParityShards configured.
	SealToRecipient bool
	// PostQuantum, with SealToRecipient, seals to a recipient using hybrid
	// X25519 + ML-KEM-768 (post-quantum "harvest now, decrypt later" resistance)
	// when that recipient advertises an ML-KEM key, falling back to classical
	// X25519 sealing for peers without one. Each node advertises an ephemeral
	// ML-KEM public key when this is set.
	//
	// Scope: this hardens the SDK's transport/content seal only. It does NOT make
	// any encryption layer an application builds on top (e.g. a messenger's
	// per-contact end-to-end keys) post-quantum — that remains the app's own
	// responsibility.
	PostQuantum bool
	// AutoRelay enables AutoNAT: instead of setting NeedsRelay by hand, the node
	// periodically asks peers to dial its data port back and, if it concludes it
	// is unreachable, automatically holds circuit reservations (and drops them if
	// it becomes reachable again). A manually-set NeedsRelay still forces
	// reservations regardless. Recommended for clients that may or may not be
	// behind NAT.
	AutoRelay bool
	// OnReachabilityChange, if set, is called with AutoNAT's conclusion whenever it
	// flips (true = this node is dial-able from outside, false = not). Enables
	// reachability observation independently of AutoRelay — e.g. to start relaying
	// only while reachable via SetRelay. Fires from a background goroutine.
	OnReachabilityChange func(reachable bool)
	// AdaptiveOnionHops chooses the onion path length per send from the diversity
	// of available relays (distinct subnets), instead of the fixed HopCount, so a
	// send is "as anonymous as the swarm currently allows": more independent relays
	// -> more hops, capped at MaxOnionHops (practical max 3). It is always
	// fail-closed — a send that cannot meet MinOnionHops errors rather than going
	// direct — so combine it with the anonymous profile for "always anonymous".
	// When set, it overrides HopCount for routing.
	AdaptiveOnionHops bool
	// MinOnionHops is the floor for AdaptiveOnionHops: below it a send fails rather
	// than routing with too little anonymity. 0 means 1.
	MinOnionHops int
	// MaxOnionHops is the ceiling for AdaptiveOnionHops. 0 means the built-in cap
	// of 3.
	MaxOnionHops int
	// AdaptiveRedundancy scales the number of independent paths each fragment is
	// sent over with relay diversity (distinct subnets), instead of the fixed
	// Redundancy, so resilience grows as the network grows without over-sending on
	// a small swarm. Bounded by MinRedundancy/MaxRedundancy.
	AdaptiveRedundancy bool
	// MinRedundancy is the floor for AdaptiveRedundancy (a young/thin network still
	// gets at least this many paths). 0 means 1.
	MinRedundancy int
	// MaxRedundancy is the ceiling for AdaptiveRedundancy. 0 means the built-in cap
	// (4), so a large swarm doesn't fan out over unbounded paths.
	MaxRedundancy int
	// StrictAnonymity makes an anonymous send (HopCount > 0) fail with an error
	// when no forwarded route can be built (e.g. no relay is available), instead of
	// silently degrading to a direct send that would reveal the sender's address to
	// the recipient. Off by default (delivery is preferred over anonymity); enable
	// it when anonymity is a hard requirement. Applies to SendTo/SendData and
	// SendStream; broadcasts and non-anonymous sends (HopCount == 0) are unaffected.
	StrictAnonymity bool
	// Redundancy is the number of independent paths each fragment is sent over
	// when forwarding (HopCount > 0). Higher values survive more relays dropping
	// traffic at the cost of bandwidth. 0 or 1 means a single path.
	Redundancy int
	// DiscoveryPort is the UDP port for peer discovery. 0 uses the well-known
	// default (64512); a negative value requests an ephemeral port (read back
	// with DiscoveryPort()), which allows several nodes per host.
	DiscoveryPort int
	// DataPort is the TCP port for data/relay transfer. 0 uses the well-known
	// default (64513); a negative value requests an ephemeral port (read back
	// with DataPort()).
	DataPort int
	// DataShards and ParityShards enable Reed-Solomon erasure coding when both
	// are > 0: a payload is encoded into DataShards data + ParityShards parity
	// shards, and the destination can reconstruct from ANY DataShards of them —
	// so up to ParityShards may be dropped by unreliable relays. Requires Key to
	// be set. Zero means plain sequential chunking.
	DataShards   int
	ParityShards int
	// ConfirmDelivery makes SendTo/SendVariableTo wait for the destination's
	// end-to-end acknowledgement and resend on timeout, returning an error if the
	// transfer is never confirmed. Applies to targeted sends only (not broadcast).
	ConfirmDelivery bool
	// CoverTraffic emits decoy traffic indistinguishable from real forwarded
	// transfers, so observers cannot tell when this node is actually sending.
	// Requires HopCount >= 1 and available relays.
	CoverTraffic bool
	// PadCellSize, when > 0, pads forwarded packets up to a multiple of this many
	// bytes so payload length is not inferable from packet size.
	PadCellSize int
	// RelayJitter, when > 0, makes this node (as a relay) delay forwarding by a
	// random duration up to this bound, blunting timing correlation.
	RelayJitter time.Duration
	// StoreForward makes this node (as a relay) hold undeliverable fragments for
	// an offline recipient and flush them when the recipient reconnects (reserves)
	// — enabling delivery to peers that are temporarily offline.
	StoreForward bool
	// StoreForwardTTL bounds how long a held fragment is kept (0 = default).
	StoreForwardTTL time.Duration
	// SubChunkSize caps a single fragment's on-wire payload in bytes; a larger
	// fragment (typically a big Reed-Solomon shard) is split into transport-sized
	// sub-chunks and reassembled by the receiver, bounding per-packet memory for
	// large payloads. 0 uses the default (4 MiB).
	SubChunkSize int
	// RelayScoring periodically challenges relays to forward a self-addressed
	// probe; a relay that fails RelayStrikeLimit consecutive challenges is
	// excommunicated (excluded from routing) for RelayPenance. Useful when routing
	// through untrusted relays, to route around silent droppers.
	RelayScoring bool
	// RelayStrikeLimit is the consecutive failures before excommunication (0 = default 3).
	RelayStrikeLimit int
	// RelayPenance is how long an excommunication lasts (0 = default 1h).
	RelayPenance time.Duration
	// TraceHops enables a local, bounded ring of this node's recent hop events
	// (send/receive/forward/deliver/decoy/drop), readable via HopTrace() for
	// diagnostics. It is node-local — no cross-relay correlation ID is put on the
	// wire — so it never weakens forwarded-traffic anonymity. Off by default.
	TraceHops bool
	// TraceSize bounds the hop-trace ring (0 = default 256 events).
	TraceSize int
	// OnStreamReceived, when set, provides an io.WriteCloser to flush an incoming
	// streamed transfer into (completed blocks written in order, then Closed),
	// bounding receive-side memory. When nil, a streamed transfer is buffered and
	// delivered via OnDataReceived instead.
	OnStreamReceived func(id [32]byte) io.WriteCloser
	// StreamBlockSize sets the per-block plaintext size for SendStream (0 =
	// default 4 MiB). Smaller blocks bound memory tighter at some overhead cost.
	StreamBlockSize int
}

const (
	defaultDiscoveryPort = 64512
	defaultDataPort      = transfer.DataPort
)

// Profile names a coherent bundle of privacy/reliability settings, so callers
// don't have to reason about the individual HopCount/Redundancy/CoverTraffic/…
// knobs and risk an incoherent combination. See Preset.
type Profile string

const (
	// ProfileDirect is fastest and least private: no relay hops (so sender and
	// recipient are linkable at the IP layer), a single path, no cover traffic.
	// Use only when anonymity is not required.
	ProfileDirect Profile = "direct"
	// ProfileBalanced routes through one relay over redundant paths with relay
	// scoring — a reasonable default for most applications.
	ProfileBalanced Profile = "balanced"
	// ProfileAnonymous maximizes sender anonymity and traffic-analysis
	// resistance: multiple hops, redundant paths, cover traffic, size padding,
	// relay jitter, and scoring. It costs latency and bandwidth and needs relays
	// available in the swarm.
	ProfileAnonymous Profile = "anonymous"
)

// Preset returns an Options pre-filled with a coherent bundle of privacy and
// reliability settings for the given profile. Set the remaining fields (Key,
// StorageDir, callbacks, ports, …) on the returned value:
//
//	opts := swarmsync.Preset(swarmsync.ProfileAnonymous)
//	opts.Key = key
//	opts.StorageDir = "./data"
//	opts.OnDataReceived = handler
//	node, _ := swarmsync.New(opts)
//
// An unrecognized profile returns ProfileBalanced's settings.
func Preset(p Profile) Options {
	switch p {
	case ProfileDirect:
		return Options{
			HopCount:     0,
			Redundancy:   1,
			RelayScoring: false,
		}
	case ProfileAnonymous:
		return Options{
			HopCount:     2,
			Redundancy:   2,
			CoverTraffic: true,
			PadCellSize:  512,
			RelayJitter:  250 * time.Millisecond,
			RelayScoring: true,
		}
	default: // ProfileBalanced (also the fallback for unknown profiles)
		return Options{
			HopCount:     1,
			Redundancy:   2,
			RelayScoring: true,
		}
	}
}

// resolvePort maps an Options port to an actual bind port: a negative value
// requests an ephemeral port (0), 0 selects the well-known default, and any
// other value is used as-is.
func resolvePort(p, def int) int {
	switch {
	case p < 0:
		return 0
	case p == 0:
		return def
	default:
		return p
	}
}

// SyncSwarm represents a node in the swarm network
type SyncSwarm struct {
	opts      Options
	selfID    string
	discovery *discovery.Discovery
	storage   *storage.Storage
	transfer  *transfer.Transfer
	metrics   *monitoring.Metrics
	mu        sync.RWMutex
	running   bool
}

// New creates a new SyncSwarm instance
func New(opts Options) (*SyncSwarm, error) {
	if opts.StorageDir == "" {
		opts.StorageDir = filepath.Join(os.TempDir(), "swarmsync")
	}
	if len(opts.Key) != 0 && len(opts.Key) != 32 {
		return nil, fmt.Errorf("Key must be a 32-byte AES-256 key, got %d bytes", len(opts.Key))
	}

	// Create storage directory. 0700: it holds this node's private Ed25519
	// identity seed and sealed data, so it must not be traversable by other local
	// users.
	if err := os.MkdirAll(opts.StorageDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Load (or create) this node's persistent Ed25519 identity. The node's ID is
	// derived from the public key, so it cannot be spoofed by another node, and
	// every packet this node sends is signed with the private key.
	signPriv, signPub, err := encryption.LoadOrCreateIdentity(opts.StorageDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load node identity: %w", err)
	}
	selfID := protocol.DeriveNodeID(signPub)

	// Initialize components
	store, err := storage.NewStorage(opts.StorageDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	disc, err := discovery.NewDiscovery(selfID, resolvePort(opts.DiscoveryPort, defaultDiscoveryPort))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize discovery: %w", err)
	}
	disc.SetSigningKey(signPriv)

	// Generate this node's X25519 (onion) key. Its public key is advertised so
	// other nodes can wrap forwarded traffic toward it; the private key lets
	// this node peel layers addressed to it. It is authenticated by the signed,
	// identity-bound discovery packet that advertises it.
	nodePriv, nodePub, err := encryption.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate node onion key: %w", err)
	}

	// Dispatch reassembled payloads: gob-decoded variables go to
	// OnVariableReceived, raw bytes to OnDataReceived. (Callers must
	// gob.Register their concrete types for variable decoding to succeed.)
	onData := func(data []byte, variable bool) {
		if variable {
			if opts.OnVariableReceived != nil {
				var env variableEnvelope
				if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&env); err == nil {
					opts.OnVariableReceived(env.V)
				}
			}
			return
		}
		if opts.OnDataReceived != nil {
			opts.OnDataReceived(data)
		}
	}

	trans, err := transfer.NewTransfer(disc, store, selfID, opts.Key, onData, nodePriv, signPriv, opts.HopCount, opts.Redundancy, opts.DataShards, opts.ParityShards, opts.ConfirmDelivery, resolvePort(opts.DataPort, defaultDataPort))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize transfer: %w", err)
	}

	// Advertise the actual data port the transfer listener bound (which may be
	// an ephemeral port), so peers dial the right place.
	var capabilities []string
	if opts.Relay {
		capabilities = append(capabilities, "relay")
	}
	disc.SetIdentity(nodePub.Bytes(), uint16(trans.Port()), capabilities)
	// Bootstrap set = caller-supplied peers plus the baked-in default seeds
	// (unless opted out), so a node with no configuration can still join. As the
	// network grows and nodes cache peers, no single seed stays load-bearing.
	boot := append([]string(nil), opts.BootstrapPeers...)
	if !opts.DisableDefaultSeeds {
		boot = append(boot, DefaultSeeds...)
	}
	disc.SetBootstrapPeers(boot)
	// Persist and reload known peers across restarts, further reducing seed
	// dependence, when we have a storage directory.
	if opts.StorageDir != "" {
		disc.SetPeerCache(filepath.Join(opts.StorageDir, "discovery-peers.json"))
	}
	// Apply the bridge PSK before any bridge is created, so both the listener and
	// every outbound bridge are gated by it.
	if len(opts.BridgePSK) > 0 {
		// Warn rather than refuse: the key is opt-in, so a caller has clearly asked
		// for the gate — but a key this short offers little, and failing silently
		// would leave them believing the bridge is protected when it is barely.
		if len(opts.BridgePSK) < MinBridgePSKLen {
			log.Printf("syncswarm: BridgePSK is %d bytes; use at least %d — a short key "+
				"can be recovered offline from one captured handshake",
				len(opts.BridgePSK), MinBridgePSKLen)
		}
		disc.SetBridgePSK(opts.BridgePSK)
	}
	// Accept inbound bridges when configured (transport-node role).
	if opts.BridgeListen != "" {
		if _, err := disc.AddListenBridge("bridge-listen", opts.BridgeListen); err != nil {
			log.Printf("syncswarm: bridge listener on %s failed: %v", opts.BridgeListen, err)
		}
	}
	// Open TCP bridges to known transport nodes so discovery crosses subnets. A
	// bridge that cannot be dialed now is skipped rather than failing startup.
	for _, addr := range opts.BridgePeers {
		if err := disc.AddBridge("bridge-"+addr, addr); err != nil {
			log.Printf("syncswarm: bridge to %s unavailable: %v", addr, err)
		}
	}
	// Zero-config LAN discovery. A host with no multicast interface (loopback-only
	// container) just gets no LAN peering — not a fatal condition.
	if opts.AutoInterface {
		if err := disc.AddAutoInterface("auto-lan"); err != nil {
			log.Printf("syncswarm: zero-config LAN discovery unavailable: %v", err)
		}
	}
	// Radio interfaces (LoRa / serial). A device that can't be opened (missing,
	// permissions, unsupported OS) is logged, not fatal — the node still runs over
	// its IP interfaces.
	if opts.LoRaDevice != "" {
		if err := disc.AddLoRaInterface("lora0", opts.LoRaDevice, opts.LoRaBaud, opts.LoRaDutyCycle); err != nil {
			log.Printf("syncswarm: LoRa interface on %s unavailable: %v", opts.LoRaDevice, err)
		}
	}
	if opts.SerialDevice != "" {
		if err := disc.AddSerialInterface("serial0", opts.SerialDevice, opts.SerialBaud, opts.SerialDutyCycle); err != nil {
			log.Printf("syncswarm: serial interface on %s unavailable: %v", opts.SerialDevice, err)
		}
	}
	trans.SetNeedsRelay(opts.NeedsRelay)
	trans.SetAutoRelay(opts.AutoRelay)
	trans.SetStrictAnonymity(opts.StrictAnonymity)
	trans.SetOnionOverLinks(opts.OnionOverLinks)
	if opts.OnDeliveryConfirmed != nil {
		trans.SetOnDelivered(opts.OnDeliveryConfirmed)
	}
	trans.SetPerHopRouting(opts.PerHopRouting)
	trans.SetAdaptiveOnion(opts.AdaptiveOnionHops, opts.MinOnionHops, opts.MaxOnionHops)
	trans.SetAdaptiveRedundancy(opts.AdaptiveRedundancy, opts.MinRedundancy, opts.MaxRedundancy)
	// Deprioritize the default seeds as relays: a seed should serve first contact,
	// not carry general traffic. Resolve their hostnames to IPs so path selection
	// can match them against learned relay addresses.
	if !opts.DisableDefaultSeeds {
		trans.SetSeedHosts(resolveSeedHosts(DefaultSeeds))
	}
	trans.SetSealToRecipient(opts.SealToRecipient)
	if opts.PostQuantum {
		// Generate an ephemeral ML-KEM-768 key, advertise its public half, and
		// install the decapsulation key so peers can seal to us post-quantum.
		if decap, err := encryption.GenerateMLKEMKey(); err == nil {
			disc.SetMLKEMKey(decap.EncapsulationKey().Bytes())
			trans.SetPostQuantum(true, decap)
		}
	}
	if opts.AutoRelay || opts.OnReachabilityChange != nil {
		// AutoNAT: enable reservations when discovery concludes we're unreachable
		// (a manually-set NeedsRelay still wins), and surface the conclusion to the
		// app so it can, e.g., start/stop relaying based on reachability.
		disc.EnableReachabilityChecks(func(reachable bool) {
			if opts.AutoRelay {
				trans.SetNeedsRelay(opts.NeedsRelay || !reachable)
			}
			if opts.OnReachabilityChange != nil {
				opts.OnReachabilityChange(reachable)
			}
		})
	}
	trans.SetAnonymity(opts.CoverTraffic, opts.PadCellSize, opts.RelayJitter)
	trans.SetStoreForward(opts.StoreForward, opts.StoreForwardTTL)
	trans.SetSubChunkSize(opts.SubChunkSize)
	trans.SetStreamBlockSize(opts.StreamBlockSize)
	trans.SetStreamSink(opts.OnStreamReceived)
	trans.SetTracing(opts.TraceHops, opts.TraceSize)
	trans.SetRelayScoring(opts.RelayScoring, opts.RelayStrikeLimit, opts.RelayPenance)

	metrics := monitoring.New()
	trans.SetMetrics(metrics)

	s := &SyncSwarm{
		opts:      opts,
		selfID:    selfID,
		discovery: disc,
		storage:   store,
		transfer:  trans,
		metrics:   metrics,
	}

	return s, nil
}

// Stats returns a snapshot of this node's transfer activity counters.
func (s *SyncSwarm) Stats() monitoring.Snapshot {
	return s.metrics.Snapshot()
}

// PeerHealth returns the current composition and lifetime churn of this node's
// peer table (active/inactive counts, per-subnet distribution, joins/evictions).
func (s *SyncSwarm) PeerHealth() discovery.PeerHealth {
	return s.discovery.PeerHealth()
}

// PeerInfo describes one peer as this node currently sees it. It is deliberately
// operational rather than cryptographic: identity, where it is, whether it is
// answering, and what it offers — enough to answer "who is on my network and is
// it healthy" without exposing key material.
type PeerInfo struct {
	// ID is the peer's key-derived NodeID (what you address it by).
	ID string `json:"id"`
	// Address is the peer's discovery-port address as last observed.
	Address string `json:"address"`
	// DataPort is the TCP port the peer advertised for transfers.
	DataPort uint16 `json:"data_port"`
	// Latency is the last measured round trip. Exposed to Go callers as a
	// Duration; JSON consumers get LatencyMS, which is friendlier at a shell.
	Latency time.Duration `json:"-"`
	// LatencyMS is Latency in milliseconds, for JSON/operator use.
	LatencyMS float64 `json:"latency_ms"`
	// Active reports whether the peer is currently passing liveness checks. An
	// inactive peer is still listed — that is usually the one worth looking at.
	Active bool `json:"active"`
	// LastSeen is when we last heard from the peer.
	LastSeen time.Time `json:"last_seen"`
	// Capabilities are the peer's advertised roles, e.g. ["relay"].
	Capabilities []string `json:"capabilities,omitempty"`
	// RelayIDs are the relays this peer is reachable through, when it is behind
	// NAT and holding circuit reservations.
	RelayIDs []string `json:"relay_ids,omitempty"`
}

// Peers returns every peer this node currently knows about — active and
// inactive — sorted by NodeID for stable output. Where PeerHealth gives you
// aggregate shape, this answers "who, specifically", which is what you need when
// diagnosing whether the peers you expect are actually there.
func (s *SyncSwarm) Peers() []PeerInfo {
	nodes := s.discovery.AllNodes()
	out := make([]PeerInfo, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, PeerInfo{
			ID:           n.ID,
			Address:      n.Address,
			DataPort:     n.Port,
			Latency:      n.Latency,
			LatencyMS:    float64(n.Latency) / float64(time.Millisecond),
			Active:       n.Active,
			LastSeen:     n.LastSeen,
			Capabilities: n.Capabilities,
			RelayIDs:     n.RelayIDs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// FindNode locates a peer by its node ID using the Kademlia DHT, even when the
// peer is not already in this node's local table — it iteratively queries
// successively closer peers. It returns true once the node is located (and
// learned locally, so a subsequent SendTo can reach it). Requires a network with
// DHT-capable peers; returns false if the node cannot be found.
func (s *SyncSwarm) FindNode(nodeID string) bool {
	_, ok := s.discovery.FindNode(nodeID)
	return ok
}

// HopTrace returns this node's recent local hop events when tracing is enabled
// (Options.TraceHops), oldest first. It is node-local by design: no correlation
// identifier crosses relays on the wire, so it never de-anonymizes forwarded
// traffic. Empty when tracing is off.
func (s *SyncSwarm) HopTrace() []transfer.HopEvent {
	return s.transfer.HopTrace()
}

// NodeID returns this node's self-authenticating identity, derived from its
// Ed25519 public key. Share it out-of-band; peers address this node by it
// (SendTo/SendVariableTo), and it cannot be claimed by any other node.
func (s *SyncSwarm) NodeID() string {
	return s.selfID
}

// Start begins listening for incoming data
func (s *SyncSwarm) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	s.discovery.Start()
	// Deliver messages arriving over encrypted Links to the same callback as the
	// transport path, reassembling multi-frame messages.
	if lm := s.discovery.Links(); lm != nil {
		lm.OnInboundLink(func(l *link.Link) {
			deliver := func(data []byte) {
				if s.opts.OnDataReceived != nil {
					s.opts.OnDataReceived(data)
				}
			}
			// One Router per inbound link demuxes best-effort messages, reliable
			// resources (both delivered to the app), and onion relay blobs (peeled and
			// forwarded by the transfer layer).
			router := link.NewRouter(l)
			router.OnMessage(deliver)
			router.OnResource(func(_ [16]byte, data []byte) { deliver(data) })
			router.OnRelay(s.transfer.HandleRelayBlobAsync)
		})
	}
	s.transfer.Start()
	s.running = true

	return nil
}

// linkDialTimeout bounds how long SendToLink waits for the Link handshake.
const linkDialTimeout = 5 * time.Second

// SendToLink sends data to nodeID over an encrypted, forward-secret Link
// established over whatever interface reaches the node (UDP or a bridge). Unlike
// SendTo it uses neither erasure coding, onion routing, nor the shared content
// key: confidentiality and integrity come from the Link's per-session key, which
// is authenticated to the recipient's node identity. The receiver delivers the
// bytes via OnDataReceived. Best-effort for multi-frame payloads over a datagram
// transport; the application layer confirms/retries.
func (s *SyncSwarm) SendToLink(nodeID string, data []byte) error {
	l, err := s.discovery.DialNode(nodeID, linkDialTimeout)
	if err != nil {
		return err
	}
	return link.NewRouter(l).SendMessage(data)
}

// resourceTransferTimeout bounds a reliable resource transfer end to end.
const resourceTransferTimeout = 60 * time.Second

// SendToResource sends data to nodeID **reliably** over an encrypted, forward-secret
// Link using the Resource layer: the payload is segmented, windowed, and
// retransmitted with selective ACKs until the recipient has all of it, then this
// returns. Unlike SendTo it needs no shared content key, erasure coding, or onion
// routing (confidentiality/integrity come from the Link's per-session key,
// authenticated to the recipient's identity), and unlike SendToLink it is reliable
// over lossy/datagram/radio transports — and it works over any interface a Link
// reaches (UDP, a TCP bridge, LAN multicast, LoRa). The receiver delivers the bytes
// via OnDataReceived. This is the Phase 0b.2 direct-transfer-over-Link path.
func (s *SyncSwarm) SendToResource(nodeID string, data []byte) error {
	l, err := s.discovery.DialNode(nodeID, linkDialTimeout)
	if err != nil {
		return err
	}
	if err := link.NewRouter(l).SendResource(data, resourceTransferTimeout); err != nil {
		// The cached link may be stale (peer restarted); close it so the next
		// send re-dials a fresh session instead of reusing a dead one.
		l.Close()
		return err
	}
	return nil
}

// Stop halts all swarm activities
func (s *SyncSwarm) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.discovery.Stop()
	s.transfer.Stop()
	s.running = false

	return nil
}

// DiscoveryPort returns the actual UDP port this node's discovery service is
// bound to (useful when an ephemeral port was requested).
func (s *SyncSwarm) DiscoveryPort() int {
	return s.discovery.Port()
}

// DataPort returns the actual TCP port this node's transfer service is bound to.
func (s *SyncSwarm) DataPort() int {
	return s.transfer.Port()
}

// Reachable reports AutoNAT's conclusion about whether this node is dial-able from
// outside. known is false until enough dial-back probes have completed (requires
// AutoRelay or OnReachabilityChange to have enabled reachability checks).
func (s *SyncSwarm) Reachable() (reachable, known bool) {
	return s.discovery.Reachable()
}

// SetRelay turns this node's advertised relay capability on or off at runtime and
// re-advertises, so a node can start forwarding for others once it learns it is
// reachable (and stop if that changes). Only advertise relay when reachable — an
// undialable relay black-holes traffic routed to it.
func (s *SyncSwarm) SetRelay(on bool) {
	s.discovery.SetRelay(on)
}

// SetBootstrapPeers sets the discovery bootstrap peer addresses. Call before
// Start; it lets callers wire peers after New has bound (possibly ephemeral)
// ports and their addresses are known.
func (s *SyncSwarm) SetBootstrapPeers(addrs []string) {
	s.discovery.SetBootstrapPeers(addrs)
}

// Bootstrap re-announces this node to its configured bootstrap peers, prompting
// mutual discovery. Useful right after a set of nodes start, or to rejoin.
func (s *SyncSwarm) Bootstrap() {
	s.discovery.Bootstrap()
}

// Send broadcasts data to all nodes in the swarm
func (s *SyncSwarm) Send(data []byte) error {
	return s.transfer.SendData(data, s.opts.Group, "", false)
}

// SendTo sends data to a specific node. With Options.ReliableLinkTransfer it uses
// the reliable Resource-over-Link path (see SendToResource); otherwise the TCP/onion
// transfer.
func (s *SyncSwarm) SendTo(data []byte, nodeID string) error {
	if s.opts.ReliableLinkTransfer {
		return s.SendToResource(nodeID, data)
	}
	return s.transfer.SendData(data, "", nodeID, false)
}

// SendToTracked is SendTo but also returns the transfer ID, so a later
// OnDeliveryConfirmed callback can be matched to this particular message.
//
// The ID is returned even when err is non-nil. That is the point: an
// ErrNotConfirmed send is exactly the one a late acknowledgement may still
// resolve, so record the ID against the message and mark it delivered if the
// callback arrives.
//
// Not supported with ReliableLinkTransfer, which has its own completion signal;
// it returns a zero ID and defers to SendTo.
func (s *SyncSwarm) SendToTracked(data []byte, nodeID string) ([32]byte, error) {
	if s.opts.ReliableLinkTransfer {
		return [32]byte{}, s.SendToResource(nodeID, data)
	}
	return s.transfer.SendDataTracked(data, "", nodeID, false)
}

// SendToAsync sends data to a specific node without blocking the caller. When
// ConfirmDelivery is enabled, SendTo otherwise blocks until the recipient's
// acknowledgement (or the resend/timeout budget is exhausted); SendToAsync runs
// that on a background goroutine and reports the outcome via done. done may be
// nil for fire-and-forget. This lets a UI trigger a confirmed send directly from
// its event thread without freezing.
func (s *SyncSwarm) SendToAsync(data []byte, nodeID string, done func(error)) {
	go func() {
		err := s.SendTo(data, nodeID)
		if done != nil {
			done(err)
		}
	}()
}

// SendAsync broadcasts data to the group without blocking the caller; see
// SendToAsync.
func (s *SyncSwarm) SendAsync(data []byte, done func(error)) {
	go func() {
		err := s.transfer.SendData(data, s.opts.Group, "", false)
		if done != nil {
			done(err)
		}
	}()
}

// SendStream erasure-codes and streams r to nodeID block by block, so the sender
// never buffers the whole payload — use it for large files or media. It requires
// a content key (Options.Key) and erasure coding (Options.DataShards/ParityShards).
// The receiver flushes into Options.OnStreamReceived's writer if set (bounded
// receive memory), else buffers and delivers via OnDataReceived. When
// Options.ConfirmDelivery is set the send blocks until the receiver acknowledges
// the whole reassembled stream (returning an error if it is not confirmed);
// otherwise it is fire-and-forget.
func (s *SyncSwarm) SendStream(r io.Reader, nodeID string) error {
	return s.transfer.SendStream(r, nodeID)
}

// SendStreamResumable streams r to nodeID with resume support, identified stably
// by streamID. If a send is interrupted, calling it again with the same streamID
// (and a fresh reader over the same content) skips the blocks the receiver already
// holds and finishes the transfer. r must be an io.ReadSeeker (a file), the block
// size must match across attempts, and the recipient must be directly reachable
// (the anonymous forwarded path is not supported). Requires Key + DataShards/
// ParityShards.
func (s *SyncSwarm) SendStreamResumable(r io.ReadSeeker, nodeID, streamID string) error {
	return s.transfer.SendStreamResumable(r, nodeID, streamID)
}

// variableEnvelope wraps a variable in an interface-typed field so gob transmits
// the concrete type name, allowing the receiver to decode it back into an
// interface value (gob cannot decode a concrete type directly into interface{}).
type variableEnvelope struct {
	V interface{}
}

func encodeVariable(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(variableEnvelope{V: v}); err != nil {
		return nil, fmt.Errorf("failed to encode variable: %w", err)
	}
	return buf.Bytes(), nil
}

// SendVariable broadcasts a variable to all nodes. Receivers deliver it via
// OnVariableReceived; register concrete types with gob.Register as needed.
func (s *SyncSwarm) SendVariable(v interface{}) error {
	b, err := encodeVariable(v)
	if err != nil {
		return err
	}
	return s.transfer.SendData(b, s.opts.Group, "", true)
}

// SendVariableTo sends a variable to a specific node.
func (s *SyncSwarm) SendVariableTo(v interface{}, nodeID string) error {
	b, err := encodeVariable(v)
	if err != nil {
		return err
	}
	return s.transfer.SendData(b, "", nodeID, true)
}
