// Package link implements Reticulum-style Links: ephemeral, end-to-end encrypted
// sessions established over any frame transport (an iface.Interface, a bridge, or
// an onion route). A Link is created by a 3-message handshake — request → proof →
// data — that gives forward secrecy (per-link ephemeral X25519 keys) and
// initiator anonymity (the request carries no initiator identity). Application
// data then flows AEAD-encrypted, addressed by a random link ID.
//
// The package is transport-agnostic: a Manager sends frames through an injected
// function and is fed inbound link packets via Deliver, so it can sit behind a
// router that demultiplexes frames by packet type. This is the session layer the
// connection-oriented transfer path will ride to reach peers over bridges and
// multi-hop routes (RETICULUM_ALIGNMENT.md, the Link/session layer).
package link

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/APoniatowski/syncswarm/internal/protocol"
)

const hkdfInfo = "syncswarm-link-v1"

// SendFunc transmits a marshaled frame to a peer address over some interface.
type SendFunc func(addr string, frame []byte) error

// requestPayload / proofPayload / dataPayload are the Link handshake and data
// bodies carried in a protocol.Packet.Payload.
type requestPayload struct {
	LinkID [16]byte
	EphPub []byte // initiator ephemeral X25519 public key
}

type proofPayload struct {
	LinkID    [16]byte
	EphPub    []byte // responder ephemeral X25519 public key
	Signature []byte // Ed25519 over LinkID||EphPub by the destination
}

type dataPayload struct {
	LinkID [16]byte
	Nonce  []byte
	Cipher []byte
}

// Link is one established encrypted session.
type Link struct {
	ID        [16]byte
	peerAddr  string
	aead      cipher.AEAD
	initiator bool // sets the nonce direction bit, so the two sides never collide
	sendCtr   atomic.Uint64
	onData    atomic.Pointer[func([]byte)]
	mgr       *Manager
}

// Manager establishes and tracks Links over one send function. self signs proofs
// so initiators can authenticate this node as a link destination.
type Manager struct {
	self ed25519.PrivateKey
	send SendFunc

	mu      sync.Mutex
	links   map[[16]byte]*Link
	pending map[[16]byte]*pendingDial

	onLink atomic.Pointer[func(*Link)] // fired when an inbound link is established
}

type pendingDial struct {
	eph         *ecdh.PrivateKey
	destSignPub ed25519.PublicKey
	result      chan *Link
}

// NewManager creates a Link manager. self is this node's Ed25519 key (used to
// sign proofs); send transmits frames.
func NewManager(self ed25519.PrivateKey, send SendFunc) *Manager {
	return &Manager{
		self:    self,
		send:    send,
		links:   make(map[[16]byte]*Link),
		pending: make(map[[16]byte]*pendingDial),
	}
}

// OnInboundLink registers a callback fired when a remote peer establishes a link
// to this node. Set link.OnData on the provided link to receive its data.
func (m *Manager) OnInboundLink(fn func(*Link)) { m.onLink.Store(&fn) }

// Dial establishes a link to a peer at addr whose Ed25519 public key is
// destSignPub (learned via discovery), returning once the proof authenticates
// the destination or the timeout elapses.
func (m *Manager) Dial(addr string, destSignPub ed25519.PublicKey, timeout time.Duration) (*Link, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}

	pd := &pendingDial{eph: eph, destSignPub: destSignPub, result: make(chan *Link, 1)}
	m.mu.Lock()
	m.pending[id] = pd
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.pending, id)
		m.mu.Unlock()
	}()

	if err := m.sendPacket(addr, protocol.PacketTypeLinkRequest, requestPayload{
		LinkID: id,
		EphPub: eph.PublicKey().Bytes(),
	}); err != nil {
		return nil, err
	}

	select {
	case l := <-pd.result:
		l.peerAddr = addr
		return l, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("link: handshake to %s timed out", addr)
	}
}

// Deliver feeds an inbound link-typed packet (request/proof/data) received at
// addr into the manager. A router demultiplexing frames by packet type calls it.
func (m *Manager) Deliver(addr string, pkt *protocol.Packet) {
	switch pkt.Type {
	case protocol.PacketTypeLinkRequest:
		m.handleRequest(addr, pkt.Payload)
	case protocol.PacketTypeLinkProof:
		m.handleProof(pkt.Payload)
	case protocol.PacketTypeLinkData:
		m.handleData(pkt.Payload)
	}
}

// handleRequest is the responder side: derive the shared key, sign a proof, and
// establish the link.
func (m *Manager) handleRequest(addr string, payload []byte) {
	var req requestPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		return
	}
	initPub, err := ecdh.X25519().NewPublicKey(req.EphPub)
	if err != nil {
		return
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	secret, err := eph.ECDH(initPub)
	if err != nil {
		return
	}
	aead, err := deriveAEAD(secret, req.LinkID)
	if err != nil {
		return
	}

	sig := ed25519.Sign(m.self, proofTranscript(req.LinkID, eph.PublicKey().Bytes()))
	if err := m.sendPacket(addr, protocol.PacketTypeLinkProof, proofPayload{
		LinkID:    req.LinkID,
		EphPub:    eph.PublicKey().Bytes(),
		Signature: sig,
	}); err != nil {
		return
	}

	l := &Link{ID: req.LinkID, peerAddr: addr, aead: aead, initiator: false, mgr: m}
	m.mu.Lock()
	m.links[req.LinkID] = l
	m.mu.Unlock()
	if fn := m.onLink.Load(); fn != nil {
		(*fn)(l)
	}
}

// handleProof is the initiator side: authenticate the destination, derive the
// shared key, and complete the pending Dial.
func (m *Manager) handleProof(payload []byte) {
	var pr proofPayload
	if err := json.Unmarshal(payload, &pr); err != nil {
		return
	}
	m.mu.Lock()
	pd := m.pending[pr.LinkID]
	m.mu.Unlock()
	if pd == nil {
		return
	}
	// Authenticate the destination: the proof must be signed by the key we
	// expected, over this link ID and the responder's ephemeral key.
	if !ed25519.Verify(pd.destSignPub, proofTranscript(pr.LinkID, pr.EphPub), pr.Signature) {
		return
	}
	respPub, err := ecdh.X25519().NewPublicKey(pr.EphPub)
	if err != nil {
		return
	}
	secret, err := pd.eph.ECDH(respPub)
	if err != nil {
		return
	}
	aead, err := deriveAEAD(secret, pr.LinkID)
	if err != nil {
		return
	}
	l := &Link{ID: pr.LinkID, aead: aead, initiator: true, mgr: m}
	m.mu.Lock()
	m.links[pr.LinkID] = l
	m.mu.Unlock()
	select {
	case pd.result <- l:
	default:
	}
}

func (m *Manager) handleData(payload []byte) {
	var d dataPayload
	if err := json.Unmarshal(payload, &d); err != nil {
		return
	}
	m.mu.Lock()
	l := m.links[d.LinkID]
	m.mu.Unlock()
	if l == nil {
		return
	}
	pt, err := l.aead.Open(nil, d.Nonce, d.Cipher, nil)
	if err != nil {
		return // forged or corrupt frame
	}
	if fn := l.onData.Load(); fn != nil {
		(*fn)(pt)
	}
}

// OnData sets the callback for decrypted application data on this link.
func (l *Link) OnData(fn func([]byte)) { l.onData.Store(&fn) }

// Send AEAD-encrypts data and transmits it over the link. Nonces are unique per
// direction (a direction bit plus a per-link counter), so the two ends never
// reuse one.
func (l *Link) Send(data []byte) error {
	nonce := make([]byte, l.aead.NonceSize())
	if l.initiator {
		nonce[0] = 0x01
	}
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], l.sendCtr.Add(1))
	ct := l.aead.Seal(nil, nonce, data, nil)
	return l.mgr.sendPacket(l.peerAddr, protocol.PacketTypeLinkData, dataPayload{
		LinkID: l.ID,
		Nonce:  nonce,
		Cipher: ct,
	})
}

// Close removes the link from the manager. It does not send a teardown frame in
// this version.
func (l *Link) Close() {
	l.mgr.mu.Lock()
	delete(l.mgr.links, l.ID)
	l.mgr.mu.Unlock()
}

func (m *Manager) sendPacket(addr string, typ protocol.PacketType, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	pkt := protocol.NewPacket(typ, data, "ANY", "")
	frame, err := pkt.MarshalBinary()
	if err != nil {
		return err
	}
	return m.send(addr, frame)
}

// deriveAEAD turns a raw ECDH secret into an AES-256-GCM cipher, binding the key
// to the link ID via HKDF.
func deriveAEAD(secret []byte, linkID [16]byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, secret, linkID[:], hkdfInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// proofTranscript is the message the destination signs: link ID concatenated
// with its ephemeral public key.
func proofTranscript(linkID [16]byte, ephPub []byte) []byte {
	t := make([]byte, 0, 16+len(ephPub))
	t = append(t, linkID[:]...)
	t = append(t, ephPub...)
	return t
}
