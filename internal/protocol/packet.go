package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

// maxFrameSize bounds a single length-prefixed packet frame on a stream.
const maxFrameSize = 64 << 20 // 64 MiB

var errMalformedPacket = errors.New("protocol: malformed packet")

// MarshalBinary encodes the packet into a compact binary form (no JSON/base64
// bloat). Field order is fixed and mirrored by UnmarshalBinary.
func (p *Packet) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 96+len(p.Payload)+len(p.SignerKey)+len(p.Signature)+len(p.ReplyBlock)+len(p.Pad))
	buf = append(buf, p.ID[:]...)
	buf = append(buf, byte(p.Type))
	buf = appendU64(buf, uint64(p.Timestamp.UnixNano()))
	buf = appendBytes(buf, []byte(p.SourceNode))
	buf = appendBytes(buf, []byte(p.DestGroup))
	buf = appendBytes(buf, []byte(p.DestNode))
	buf = appendU32(buf, p.TotalChunks)
	buf = appendU32(buf, p.ChunkNumber)
	buf = appendU32(buf, p.SubIndex)
	buf = appendU32(buf, p.SubTotal)
	buf = append(buf, boolByte(p.Streaming))
	buf = appendU32(buf, p.BlockIndex)
	buf = appendU32(buf, p.BlockLen)
	buf = append(buf, boolByte(p.Final))
	buf = append(buf, boolByte(p.HybridSealed))
	buf = append(buf, boolByte(p.PQ))
	buf = append(buf, boolByte(p.Resumable))
	buf = appendU32(buf, p.DataShards)
	buf = appendU32(buf, p.ParityShards)
	buf = appendU64(buf, p.OriginalLen)
	buf = append(buf, boolByte(p.Variable), boolByte(p.Decoy))
	buf = appendU32(buf, p.PayloadSize)
	buf = appendBytes(buf, p.Payload)
	buf = appendBytes(buf, p.SignerKey)
	buf = appendBytes(buf, p.Signature)
	buf = appendBytes(buf, p.ReplyBlock)
	buf = appendBytes(buf, p.Pad)
	return buf, nil
}

// UnmarshalBinary decodes a packet produced by MarshalBinary.
func (p *Packet) UnmarshalBinary(data []byte) error {
	r := &reader{b: data}
	copy(p.ID[:], r.take(32))
	p.Type = PacketType(r.u8())
	p.Timestamp = time.Unix(0, int64(r.u64()))
	p.SourceNode = string(r.bytes())
	p.DestGroup = string(r.bytes())
	p.DestNode = string(r.bytes())
	p.TotalChunks = r.u32()
	p.ChunkNumber = r.u32()
	p.SubIndex = r.u32()
	p.SubTotal = r.u32()
	p.Streaming = r.u8() == 1
	p.BlockIndex = r.u32()
	p.BlockLen = r.u32()
	p.Final = r.u8() == 1
	p.HybridSealed = r.u8() == 1
	p.PQ = r.u8() == 1
	p.Resumable = r.u8() == 1
	p.DataShards = r.u32()
	p.ParityShards = r.u32()
	p.OriginalLen = r.u64()
	p.Variable = r.u8() == 1
	p.Decoy = r.u8() == 1
	p.PayloadSize = r.u32()
	p.Payload = r.bytes()
	p.SignerKey = r.bytes()
	p.Signature = r.bytes()
	p.ReplyBlock = r.bytes()
	p.Pad = r.bytes()
	return r.err
}

// WritePacket writes a length-prefixed binary packet frame to w.
func WritePacket(w io.Writer, p *Packet) error {
	body, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	_, err = w.Write(frame)
	return err
}

// ReadPacket reads one length-prefixed binary packet frame from r.
func ReadPacket(r io.Reader) (*Packet, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameSize {
		return nil, errMalformedPacket
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	p := &Packet{}
	if err := p.UnmarshalBinary(body); err != nil {
		return nil, err
	}
	return p, nil
}

func appendU32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }
func appendU64(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }
func appendBytes(b, v []byte) []byte      { return append(appendU32(b, uint32(len(v))), v...) }

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// reader is a bounds-checked cursor over a byte slice.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = errMalformedPacket
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte {
	d := r.take(1)
	if len(d) == 1 {
		return d[0]
	}
	return 0
}

func (r *reader) u32() uint32 {
	if d := r.take(4); len(d) == 4 {
		return binary.BigEndian.Uint32(d)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if d := r.take(8); len(d) == 8 {
		return binary.BigEndian.Uint64(d)
	}
	return 0
}

// bytes reads a uint32-length-prefixed slice, copied so it does not alias the
// (possibly reused) source buffer.
func (r *reader) bytes() []byte {
	n := int(r.u32())
	d := r.take(n)
	if d == nil {
		return nil
	}
	out := make([]byte, len(d))
	copy(out, d)
	return out
}

// PacketType defines the type of packet being transmitted
type PacketType uint8

const (
	PacketTypeData PacketType = iota
	PacketTypeDiscovery
	PacketTypeLatencyCheck
	PacketTypeLatencyReply
	PacketTypeAcknowledgement

	// PacketTypePeerExchange (5) carries a node's known-peer table for gossip
	// discovery. Its Payload is a JSON-marshaled PeerExchangePayload.
	PacketTypePeerExchange

	// PacketTypeRelay (6) carries an onion-wrapped blob for hop-by-hop
	// forwarding. The blob lives directly in Packet.Payload; this package does
	// NOT define the onion layer format (that lives in internal/encryption).
	//
	// The receiver peels exactly one layer with its node X25519 private key to
	// learn either "forward to NextAddr" (re-wrapped inner blob for the next
	// hop) or "final — deliver locally". Each hop repeats until the final hop
	// is reached.
	PacketTypeRelay

	// PacketTypeReservation (7) is sent by a node that cannot accept inbound
	// connections (e.g. behind NAT) over a persistent connection to a relay. The
	// relay holds the connection open and forwards the node's inbound traffic
	// back over it (a circuit relay).
	PacketTypeReservation

	// PacketTypeFindNode (8) is a Kademlia FIND_NODE query: the sender asks the
	// recipient for the contacts it knows closest to a target node ID. Its
	// Payload is a JSON-marshaled FindNodePayload.
	PacketTypeFindNode

	// PacketTypeFindNodeReply (9) answers a FIND_NODE with up to k closest
	// contacts. Its Payload is a JSON-marshaled FindNodeReplyPayload.
	PacketTypeFindNodeReply

	// PacketTypeReachabilityCheck (10) asks a peer to test whether this node's
	// data port is reachable from outside by dialing it back (AutoNAT). Its
	// Payload is a JSON-marshaled ReachabilityPayload.
	PacketTypeReachabilityCheck

	// PacketTypeReachabilityResult (11) reports the outcome of a dial-back,
	// echoing the request Nonce. Its Payload is a JSON-marshaled
	// ReachabilityPayload with Reachable set.
	PacketTypeReachabilityResult

	// PacketTypeAnnounce (12) is a self-signed identity + reachability broadcast
	// that transport nodes flood across interfaces (Reticulum-style), so a
	// destination becomes reachable network-wide without DNS or a bootstrap
	// server. Its Payload is a JSON-marshaled AnnouncePayload; the announce
	// carries its own Ed25519 signature (proof of key possession) independent of
	// the packet signature, so it stays verifiable after being re-forwarded.
	PacketTypeAnnounce

	// PacketTypePathRequest (13) asks the network for a path to a destination
	// hash the requester has no route to; a transport node holding the path
	// answers by re-flooding that destination's announce. Wired in a later phase.
	PacketTypePathRequest

	// PacketTypeLinkRequest (14) initiates an ephemeral encrypted session (a
	// Link): it carries the initiator's ephemeral X25519 public key and a random
	// link ID. The initiator stays anonymous (no identity in the request).
	PacketTypeLinkRequest

	// PacketTypeLinkProof (15) answers a link request with the responder's
	// ephemeral X25519 public key and an Ed25519 signature over the link ID and
	// that key, so the initiator authenticates the destination and both sides
	// derive the same forward-secret session key.
	PacketTypeLinkProof

	// PacketTypeLinkData (16) carries AEAD-encrypted application data over an
	// established Link, addressed by link ID.
	PacketTypeLinkData
)

// Packet represents the basic unit of data transmission in SyncSwarm
type Packet struct {
	// Header information
	ID        [32]byte   // SHA-256 hash of content + timestamp
	Type      PacketType // Type of packet
	Timestamp time.Time  // Time of packet creation

	// Routing information
	SourceNode string // Origin node identifier
	DestGroup  string // Target group (or "ANY")
	DestNode   string // Target node (or empty for group-wide)

	// Chunking information
	TotalChunks uint32 // Total number of shards/chunks in the complete transmission
	ChunkNumber uint32 // Current shard/chunk index (0-based)

	// Sub-chunking: a single logical fragment/shard whose sealed payload exceeds
	// the transport size is split into SubTotal transport-sized pieces that share
	// ChunkNumber; SubIndex is this piece's 0-based position within the fragment.
	// SubTotal <= 1 means the fragment is carried whole in this one packet. The
	// receiver reassembles the pieces into the fragment before reassembly proper.
	SubIndex uint32
	SubTotal uint32

	// Streaming (block-wise RS) metadata. When Streaming is true the transfer is
	// cut into independently erasure-coded blocks so neither end buffers the whole
	// payload: BlockIndex is this fragment's 0-based block, BlockLen the block's
	// pre-encoding byte length (needed to trim RS padding since the total length
	// is unknown up front), and Final marks a fragment of the last block.
	Streaming  bool
	BlockIndex uint32
	BlockLen   uint32
	Final      bool

	// HybridSealed marks that fragment payloads are sealed to the recipient's
	// public key (per-recipient E2E) rather than a shared symmetric key, so the
	// receiver opens them with its own node private key.
	HybridSealed bool

	// PQ marks that HybridSealed uses post-quantum hybrid sealing (X25519 +
	// ML-KEM-768) rather than X25519 alone.
	PQ bool

	// Resumable marks a streaming transfer whose receiver retains partial progress
	// across a dropped connection, so a re-send with the same transfer ID resumes
	// where it left off. On the init acknowledgement, ChunkNumber carries the next
	// block index the receiver still needs (the resume point).
	Resumable bool

	// Erasure-coding metadata. When DataShards > 0 the transmission is
	// Reed-Solomon encoded: TotalChunks == DataShards+ParityShards, and the
	// original payload can be reconstructed from ANY DataShards of them.
	// OriginalLen is the pre-encoding byte length, used to trim padding.
	// When DataShards == 0 the transmission is a plain sequential chunk stream.
	DataShards   uint32
	ParityShards uint32
	OriginalLen  uint64

	// Variable is true when the reassembled payload is a gob-encoded value
	// (delivered via OnVariableReceived) rather than raw bytes.
	Variable bool

	// ReplyBlock is an optional single-use, onion-wrapped return path the
	// recipient uses to acknowledge delivery without learning the sender's
	// identity or address. Present only on anonymously-forwarded transfers.
	ReplyBlock []byte

	// Decoy marks a cover-traffic packet: it is routed like real traffic so
	// observers cannot distinguish it, but the final recipient silently drops it.
	Decoy bool

	// Pad is unused filler that normalizes a packet's on-wire size so payload
	// length is not inferable from packet size. Ignored by all logic.
	Pad []byte

	// Content
	PayloadSize uint32 // Size of payload in bytes
	Payload     []byte // Actual data being transmitted

	// Verification
	SignerKey []byte // Ed25519 public key of the signer (self-authenticating)
	Signature []byte // Ed25519 signature over the packet's canonical bytes
}

// DiscoveryPayload represents the data structure for node discovery
type DiscoveryPayload struct {
	NodeID       string   // Unique identifier of the node
	Version      string   // Protocol version
	Capabilities []string // Node capabilities; includes "relay" when the node is willing to forward traffic for others
	Port         uint16   // Port for direct communication
	Nonce        uint64   // Correlates latency check requests with replies
	PubKey       []byte   // X25519 public key (raw bytes) so senders can onion-wrap toward this node
	SignKey      []byte   // Ed25519 public key; NodeID must equal DeriveNodeID(SignKey)
	ObservedAddr string   // the source address the sender was observed at (reflexive/STUN-like)
	RelayIDs     []string // NodeIDs of relays this node holds circuit reservations with
	MLKEMPub     []byte   // optional ML-KEM-768 public key for post-quantum hybrid sealing
}

// PeerInfo is a node's advertised routing/identity record, shared via gossip.
type PeerInfo struct {
	NodeID       string
	Address      string   // host:port the node is reachable at
	PubKey       []byte   // X25519 public key (raw)
	SignKey      []byte   // Ed25519 public key; NodeID must equal DeriveNodeID(SignKey)
	Port         uint16   // transfer/data port the node listens on
	Capabilities []string // e.g. ["relay"]
	RelayIDs     []string // NodeIDs of relays this node holds circuit reservations with
	MLKEMPub     []byte   // optional ML-KEM-768 public key for post-quantum hybrid sealing
	LastSeen     time.Time
}

// PeerExchangePayload is the body of a PacketTypePeerExchange packet.
type PeerExchangePayload struct {
	Peers []PeerInfo
}

// DHTContact is a routable peer reference exchanged in Kademlia FIND_NODE
// traffic: enough to reach the node over UDP (Address) and to route transfers to
// it (PubKey/SignKey/Port). NodeID must equal DeriveNodeID(SignKey).
type DHTContact struct {
	NodeID   string
	Address  string // host:port the node was observed at for discovery RPCs (UDP)
	PubKey   []byte // X25519 public key (raw)
	SignKey  []byte // Ed25519 public key; NodeID must equal DeriveNodeID(SignKey)
	Port     uint16 // transfer/data port
	MLKEMPub []byte // optional ML-KEM-768 public key for post-quantum hybrid sealing
}

// FindNodePayload is the body of a PacketTypeFindNode query. It both asks for
// contacts near Target and advertises the requester so the recipient can learn
// it (the requester's identity is bound via the packet signature/SignKey).
type FindNodePayload struct {
	NodeID string // requester node ID
	PubKey []byte // requester X25519 public key
	Port   uint16 // requester transfer/data port
	Target string // hex node ID being looked up
	Nonce  uint64 // correlates the reply
}

// FindNodeReplyPayload answers a FIND_NODE with the responder's closest known
// contacts to Target, echoing the request Nonce.
type FindNodeReplyPayload struct {
	Nonce    uint64
	Target   string
	Contacts []DHTContact
}

// ReachabilityPayload is the body of the AutoNAT dial-back exchange. A check
// carries the sender's DataPort (the port a peer should try to connect back to)
// and a Nonce; the result echoes the Nonce with Reachable set to whether the
// dial-back succeeded.
type ReachabilityPayload struct {
	NodeID    string
	Nonce     uint64
	DataPort  uint16
	Reachable bool
}

// NewPacket creates a new packet with the given parameters
func NewPacket(packetType PacketType, payload []byte, destGroup, destNode string) *Packet {
	now := time.Now()
	// Derive the ID over payload ++ timestamp using a fresh buffer. Appending
	// directly onto payload would write into its backing array — corrupting the
	// caller's data when payload is a sub-slice of a larger buffer (e.g. a shard
	// sub-chunk sharing capacity with its neighbours).
	nowStr := now.String()
	idSource := make([]byte, 0, len(payload)+len(nowStr))
	idSource = append(idSource, payload...)
	idSource = append(idSource, nowStr...)
	id := sha256.Sum256(idSource)

	return &Packet{
		ID:          id,
		Type:        packetType,
		Timestamp:   now,
		DestGroup:   destGroup,
		DestNode:    destNode,
		PayloadSize: uint32(len(payload)),
		Payload:     payload,
	}
}

// HexID returns the hex-encoded string form of a raw transfer ID.
func HexID(id [32]byte) string {
	const hextable = "0123456789abcdef"
	buf := make([]byte, 64)
	for i, b := range id {
		buf[i*2] = hextable[b>>4]
		buf[i*2+1] = hextable[b&0x0f]
	}
	return string(buf)
}

// canonicalBytes returns the deterministic byte representation of the packet
// used for signing and verification. The Signature field is treated as empty.
func (p *Packet) canonicalBytes() []byte {
	var buf []byte

	// Type
	buf = append(buf, byte(p.Type))

	// ID
	buf = append(buf, p.ID[:]...)

	// SourceNode, DestGroup, DestNode (length-prefixed to avoid ambiguity)
	buf = appendLenString(buf, p.SourceNode)
	buf = appendLenString(buf, p.DestGroup)
	buf = appendLenString(buf, p.DestNode)

	// ChunkNumber, TotalChunks, PayloadSize
	var num [4]byte
	binary.BigEndian.PutUint32(num[:], p.ChunkNumber)
	buf = append(buf, num[:]...)
	binary.BigEndian.PutUint32(num[:], p.TotalChunks)
	buf = append(buf, num[:]...)
	binary.BigEndian.PutUint32(num[:], p.PayloadSize)
	buf = append(buf, num[:]...)

	// Erasure-coding metadata and variable flag.
	binary.BigEndian.PutUint32(num[:], p.DataShards)
	buf = append(buf, num[:]...)
	binary.BigEndian.PutUint32(num[:], p.ParityShards)
	buf = append(buf, num[:]...)
	var num8 [8]byte
	binary.BigEndian.PutUint64(num8[:], p.OriginalLen)
	buf = append(buf, num8[:]...)

	// Sub-chunk position (bound into the signature so a relay cannot re-order or
	// re-label sub-chunks on the direct path).
	binary.BigEndian.PutUint32(num[:], p.SubIndex)
	buf = append(buf, num[:]...)
	binary.BigEndian.PutUint32(num[:], p.SubTotal)
	buf = append(buf, num[:]...)

	// Streaming block position/length and the end-of-stream marker.
	if p.Streaming {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	binary.BigEndian.PutUint32(num[:], p.BlockIndex)
	buf = append(buf, num[:]...)
	binary.BigEndian.PutUint32(num[:], p.BlockLen)
	buf = append(buf, num[:]...)
	if p.Final {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	if p.HybridSealed {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	if p.PQ {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	if p.Resumable {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	if p.Variable {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// SignerKey binds the signing key into the signed bytes so it cannot be
	// swapped for another key.
	buf = appendLenString(buf, string(p.SignerKey))

	// ReplyBlock
	buf = appendLenString(buf, string(p.ReplyBlock))

	// Decoy flag
	if p.Decoy {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// Payload
	buf = append(buf, p.Payload...)

	return buf
}

func appendLenString(buf []byte, s string) []byte {
	var num [4]byte
	binary.BigEndian.PutUint32(num[:], uint32(len(s)))
	buf = append(buf, num[:]...)
	buf = append(buf, s...)
	return buf
}

// Sign signs the packet with an Ed25519 private key, recording the signer's
// public key in SignerKey so the packet is self-authenticating. It must be
// called after all other fields are set, immediately before marshaling. A
// zero/invalid key leaves the packet unsigned (Verify will then fail).
func (p *Packet) Sign(priv ed25519.PrivateKey) {
	if len(priv) != ed25519.PrivateKeySize {
		return
	}
	p.SignerKey = priv.Public().(ed25519.PublicKey)
	p.Signature = ed25519.Sign(priv, p.canonicalBytes())
}

// Verify reports whether the packet carries a valid Ed25519 signature by the key
// in SignerKey. It authenticates the packet to whoever holds that key; callers
// that need identity binding must additionally check SourceNode/NodeID against
// DeriveNodeID(SignerKey).
func (p *Packet) Verify() bool {
	if len(p.SignerKey) != ed25519.PublicKeySize || len(p.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(p.SignerKey), p.canonicalBytes(), p.Signature)
}

// SignerID returns the key-bound node ID of the packet's signer.
func (p *Packet) SignerID() string {
	return DeriveNodeID(p.SignerKey)
}

// DeriveNodeID returns the self-authenticating node ID bound to an Ed25519
// public key: the hex of the first 16 bytes of its SHA-256 hash. A node cannot
// claim an ID without holding the corresponding key.
func DeriveNodeID(signPub []byte) string {
	if len(signPub) == 0 {
		return ""
	}
	sum := sha256.Sum256(signPub)
	return hex.EncodeToString(sum[:16])
}
