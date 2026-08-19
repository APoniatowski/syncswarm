// Package encryption provides fragment-sealing primitives for SyncSwarm.
//
// It offers two sealing paths:
//
//   - AEAD sealing with a developer-supplied symmetric key (AES-256-GCM). This
//     is the primary path and matches the project's core promise that a
//     fragment is "decrypted with a known key defined by the developer".
//   - Hybrid sealing to a recipient's X25519 public key, for the case where the
//     sender does not share a symmetric secret with the recipient.
//
// Both paths bind caller-supplied associated data (AAD) — typically the
// transfer ID and fragment index — so a sealed fragment cannot be replayed at a
// different position. Each fragment is sealed independently, so a relay that
// holds a single shard learns nothing about the plaintext.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
)

// Errors returned by the sealing primitives.
var (
	// ErrKeySize is returned when a symmetric key is not exactly 32 bytes.
	ErrKeySize = errors.New("encryption: key must be 32 bytes (AES-256)")
	// ErrCiphertextShort is returned when a ciphertext is too short to contain
	// the expected framing (nonce, ephemeral public key, or GCM tag).
	ErrCiphertextShort = errors.New("encryption: ciphertext too short")
)

// GenerateKeys generates an RSA key pair of the given bit size and writes the
// PEM-encoded private and public keys into dir. The directory is created if it
// does not already exist. Unlike the previous implementation, no filesystem
// side effects happen at package import time and the location is chosen by the
// caller rather than a hardcoded root-owned path.
func GenerateKeys(dir string, bitSize int) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return err
	}

	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	if err := os.WriteFile(dir+"/private_key.pem", privateKeyPEM, 0o600); err != nil {
		return err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	if err := os.WriteFile(dir+"/public_key.pem", publicKeyPEM, 0o644); err != nil {
		return err
	}

	return nil
}

// Sealer seals and opens fragments with authenticated encryption. The aad
// argument binds fragment metadata (e.g. transfer ID and fragment index) to the
// ciphertext so that a fragment cannot be replayed at a different position.
type Sealer interface {
	Seal(plaintext, aad []byte) (ciphertext []byte, err error)
	Open(ciphertext, aad []byte) (plaintext []byte, err error)
}

// aeadSealer implements Sealer with AES-256-GCM using a developer-supplied key.
type aeadSealer struct {
	aead cipher.AEAD
}

// NewAEADSealer returns a Sealer backed by AES-256-GCM. The key must be exactly
// 32 bytes. A fresh random nonce is generated for every Seal and prepended to
// the returned ciphertext.
func NewAEADSealer(key []byte) (Sealer, error) {
	if len(key) != 32 {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aeadSealer{aead: aead}, nil
}

// Seal encrypts plaintext, authenticates aad, and returns nonce||ciphertext.
func (s *aeadSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Seal appends the ciphertext to nonce, yielding nonce||ciphertext.
	return s.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal: it splits off the nonce, then decrypts and authenticates.
func (s *aeadSealer) Open(ciphertext, aad []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, ErrCiphertextShort
	}
	nonce, ct := ciphertext[:ns], ciphertext[ns:]
	return s.aead.Open(nil, nonce, ct, aad)
}

// hybridSealer implements Sealer by sealing to a recipient's X25519 public key
// (SealHybrid) and opening with the holder's own private key (OpenHybrid). A
// sender constructs it with the recipient's public key; a receiver with its own
// private key. This gives per-recipient end-to-end confidentiality with no shared
// symmetric key — it plugs into the same fragment/erasure-coding pipeline as the
// symmetric aeadSealer.
type hybridSealer struct {
	recipientPub *ecdh.PublicKey  // seal target (sender side); nil on a pure receiver
	myPriv       *ecdh.PrivateKey // open key (receiver side); nil on a pure sender
}

// NewHybridSealer returns a Sealer that seals to recipientPub and opens with
// myPriv. Pass the counterpart you have: a sender uses (recipientPub, nil), a
// receiver (nil, myPriv).
func NewHybridSealer(recipientPub *ecdh.PublicKey, myPriv *ecdh.PrivateKey) Sealer {
	return &hybridSealer{recipientPub: recipientPub, myPriv: myPriv}
}

func (h *hybridSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	if h.recipientPub == nil {
		return nil, errors.New("encryption: hybrid sealer has no recipient public key")
	}
	return SealHybrid(h.recipientPub, plaintext, aad)
}

func (h *hybridSealer) Open(ciphertext, aad []byte) ([]byte, error) {
	if h.myPriv == nil {
		return nil, errors.New("encryption: hybrid sealer has no private key")
	}
	return OpenHybrid(h.myPriv, ciphertext, aad)
}

// pqHybridSealer implements Sealer over the hybrid X25519 + ML-KEM-768 KEM.
type pqHybridSealer struct {
	x25519Pub  *ecdh.PublicKey            // seal target (sender)
	mlkemPub   *mlkem.EncapsulationKey768 // seal target (sender)
	x25519Priv *ecdh.PrivateKey           // open key (receiver)
	mlkemDecap *mlkem.DecapsulationKey768 // open key (receiver)
}

// NewPQHybridSealer returns a Sealer using post-quantum hybrid sealing. A sender
// passes the recipient's public keys (x25519Pub, mlkemPub, nil, nil); a receiver
// passes its own private keys (nil, nil, x25519Priv, mlkemDecap).
func NewPQHybridSealer(x25519Pub *ecdh.PublicKey, mlkemPub *mlkem.EncapsulationKey768, x25519Priv *ecdh.PrivateKey, mlkemDecap *mlkem.DecapsulationKey768) Sealer {
	return &pqHybridSealer{x25519Pub, mlkemPub, x25519Priv, mlkemDecap}
}

func (h *pqHybridSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	return SealHybridPQ(h.x25519Pub, h.mlkemPub, plaintext, aad)
}

func (h *pqHybridSealer) Open(ciphertext, aad []byte) ([]byte, error) {
	return OpenHybridPQ(h.x25519Priv, h.mlkemDecap, ciphertext, aad)
}

// GenerateMLKEMKey generates a fresh ML-KEM-768 decapsulation key; its
// EncapsulationKey().Bytes() is the public key to advertise.
func GenerateMLKEMKey() (*mlkem.DecapsulationKey768, error) { return mlkem.GenerateKey768() }

// ParseMLKEMPub parses an advertised ML-KEM-768 public key.
func ParseMLKEMPub(b []byte) (*mlkem.EncapsulationKey768, error) {
	return mlkem.NewEncapsulationKey768(b)
}

// GenerateX25519KeyPair generates an X25519 key pair for hybrid sealing.
func GenerateX25519KeyPair() (priv *ecdh.PrivateKey, pub *ecdh.PublicKey, err error) {
	priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey(), nil
}

// hkdfInfo domain-separates SyncSwarm's hybrid key derivation.
const hkdfInfo = "syncswarm/hybrid/aes-256-gcm/v1"

// deriveKey derives a 32-byte AES-256 key from an ECDH shared secret using
// HKDF-SHA256 (proper extract-and-expand with domain separation) rather than a
// bare hash.
func deriveKey(sharedSecret []byte) ([32]byte, error) {
	var k [32]byte
	out, err := hkdf.Key(sha256.New, sharedSecret, nil, hkdfInfo, len(k))
	if err != nil {
		return k, err
	}
	copy(k[:], out)
	return k, nil
}

// SealHybrid seals plaintext to recipientPub. It generates an ephemeral X25519
// key pair, performs ECDH with recipientPub, derives an AES-256 key from the
// shared secret, and AES-256-GCM seals the plaintext. The output is
// ephemeralPub||nonce||ciphertext. aad is authenticated but not encrypted.
func SealHybrid(recipientPub *ecdh.PublicKey, plaintext, aad []byte) ([]byte, error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	sealer, err := NewAEADSealer(key[:])
	if err != nil {
		return nil, err
	}
	sealed, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, err
	}

	// Prepend the ephemeral public key so the recipient can complete ECDH.
	ephPubBytes := ephPriv.PublicKey().Bytes()
	out := make([]byte, 0, len(ephPubBytes)+len(sealed))
	out = append(out, ephPubBytes...)
	out = append(out, sealed...)
	return out, nil
}

// OpenHybrid reverses SealHybrid using the recipient's private key.
func OpenHybrid(recipientPriv *ecdh.PrivateKey, ciphertext, aad []byte) ([]byte, error) {
	pubSize := len(recipientPriv.PublicKey().Bytes())
	if len(ciphertext) < pubSize {
		return nil, ErrCiphertextShort
	}
	ephPubBytes, sealed := ciphertext[:pubSize], ciphertext[pubSize:]

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(sharedSecret)
	if err != nil {
		return nil, err
	}

	sealer, err := NewAEADSealer(key[:])
	if err != nil {
		return nil, err
	}
	return sealer.Open(sealed, aad)
}

// pqHybridInfo domain-separates the hybrid X25519 + ML-KEM-768 key derivation.
const pqHybridInfo = "syncswarm/hybrid-pq/x25519+mlkem768/aes-256-gcm/v1"

// mlkem768CiphertextSize is the fixed ML-KEM-768 ciphertext length (FIPS 203).
// Asserted against the runtime output in the tests.
const mlkem768CiphertextSize = 1088

// SealHybridPQ seals plaintext to a recipient identified by BOTH an X25519 public
// key and an ML-KEM-768 encapsulation key. The AES-256 key is derived from the
// concatenation of the X25519 ECDH secret and the ML-KEM shared secret (bound to
// the transcript), so the content stays confidential as long as EITHER primitive
// is unbroken — giving post-quantum "harvest now, decrypt later" resistance while
// retaining classical security if ML-KEM were ever weakened. Output layout:
// ephX25519Pub || mlkemCiphertext || nonce||ciphertext.
func SealHybridPQ(x25519Pub *ecdh.PublicKey, mlkemPub *mlkem.EncapsulationKey768, plaintext, aad []byte) ([]byte, error) {
	if x25519Pub == nil || mlkemPub == nil {
		return nil, errors.New("encryption: SealHybridPQ requires both recipient keys")
	}
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	secretX, err := ephPriv.ECDH(x25519Pub)
	if err != nil {
		return nil, err
	}
	secretPQ, ctPQ := mlkemPub.Encapsulate()
	ephPubBytes := ephPriv.PublicKey().Bytes()

	key, err := pqHybridKey(secretX, secretPQ, ephPubBytes, ctPQ)
	if err != nil {
		return nil, err
	}
	sealer, err := NewAEADSealer(key)
	if err != nil {
		return nil, err
	}
	sealed, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(ephPubBytes)+len(ctPQ)+len(sealed))
	out = append(out, ephPubBytes...)
	out = append(out, ctPQ...)
	out = append(out, sealed...)
	return out, nil
}

// OpenHybridPQ reverses SealHybridPQ using the recipient's X25519 private key and
// ML-KEM-768 decapsulation key.
func OpenHybridPQ(x25519Priv *ecdh.PrivateKey, mlkemDecap *mlkem.DecapsulationKey768, ciphertext, aad []byte) ([]byte, error) {
	if x25519Priv == nil || mlkemDecap == nil {
		return nil, errors.New("encryption: OpenHybridPQ requires both recipient keys")
	}
	const xPubLen = 32
	if len(ciphertext) < xPubLen+mlkem768CiphertextSize {
		return nil, ErrCiphertextShort
	}
	ephPubBytes := ciphertext[:xPubLen]
	ctPQ := ciphertext[xPubLen : xPubLen+mlkem768CiphertextSize]
	sealed := ciphertext[xPubLen+mlkem768CiphertextSize:]

	ephPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, err
	}
	secretX, err := x25519Priv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	secretPQ, err := mlkemDecap.Decapsulate(ctPQ)
	if err != nil {
		return nil, err
	}

	key, err := pqHybridKey(secretX, secretPQ, ephPubBytes, ctPQ)
	if err != nil {
		return nil, err
	}
	sealer, err := NewAEADSealer(key)
	if err != nil {
		return nil, err
	}
	return sealer.Open(sealed, aad)
}

// pqHybridKey combines the two KEM shared secrets into a 32-byte AES key, binding
// the X25519 ephemeral public key and ML-KEM ciphertext into the derivation.
func pqHybridKey(secretX, secretPQ, ephXPub, ctPQ []byte) ([]byte, error) {
	combined := make([]byte, 0, len(secretX)+len(secretPQ)+len(ephXPub)+len(ctPQ))
	combined = append(combined, secretX...)
	combined = append(combined, secretPQ...)
	combined = append(combined, ephXPub...)
	combined = append(combined, ctPQ...)
	return hkdf.Key(sha256.New, combined, nil, pqHybridInfo, 32)
}

// OnionHop describes a single relay (or the final destination) on a
// source-routed onion path.
type OnionHop struct {
	NodeID string
	Addr   string          // this hop's reachable host:port
	PubKey *ecdh.PublicKey // this hop's X25519 public key
}

// OnionPeel is the result of removing exactly one onion layer. A relay learns
// only the next hop (or that it is the final recipient); it never sees the rest
// of the path.
type OnionPeel struct {
	IsFinal  bool
	NextAddr string // next hop address (empty if IsFinal)
	NextNode string // next hop node id (empty if IsFinal)
	Inner    []byte // if IsFinal: the original finalPayload; else: the onion blob to forward to NextAddr
}

// onionLayer is the internal, wire-serialized form of one onion layer. It is
// binary-encoded and then sealed to a single hop's public key. PeelOnion
// recovers it and returns it as an OnionPeel. Binary (not JSON) avoids
// base64-inflating the inner blob at every layer — a ~(4/3)^hops blowup.
type onionLayer struct {
	IsFinal  bool
	NextAddr string
	NextNode string
	Inner    []byte
}

// marshalBinary encodes a layer as: IsFinal(1) | NextAddr | NextNode | Inner,
// each variable field length-prefixed with a big-endian uint32.
func (l onionLayer) marshalBinary() []byte {
	buf := make([]byte, 0, 1+12+len(l.NextAddr)+len(l.NextNode)+len(l.Inner))
	if l.IsFinal {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = appendLenField(buf, []byte(l.NextAddr))
	buf = appendLenField(buf, []byte(l.NextNode))
	buf = appendLenField(buf, l.Inner)
	return buf
}

func unmarshalLayer(data []byte) (onionLayer, error) {
	var l onionLayer
	if len(data) < 1 {
		return l, errors.New("encryption: truncated onion layer")
	}
	l.IsFinal = data[0] == 1
	rest := data[1:]
	fields := make([][]byte, 0, 3)
	for i := 0; i < 3; i++ {
		if len(rest) < 4 {
			return l, errors.New("encryption: truncated onion layer")
		}
		n := int(binary.BigEndian.Uint32(rest[:4]))
		rest = rest[4:]
		if n < 0 || len(rest) < n {
			return l, errors.New("encryption: truncated onion layer")
		}
		f := make([]byte, n)
		copy(f, rest[:n])
		fields = append(fields, f)
		rest = rest[n:]
	}
	l.NextAddr, l.NextNode, l.Inner = string(fields[0]), string(fields[1]), fields[2]
	return l, nil
}

func appendLenField(b, v []byte) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(v))), v...)
}

// BuildOnion constructs a source-routed onion for the given path. hops[0] is the
// first relay the sender dials and hops[len-1] is the final destination. Each
// layer is sealed with SealHybrid to that hop's public key, so a relay can peel
// exactly one layer and learn only the next hop.
//
// The layers are built innermost (destination) to outermost (first relay); the
// returned blob is what the sender sends to hops[0].Addr.
func BuildOnion(hops []OnionHop, finalPayload []byte) ([]byte, error) {
	if len(hops) == 0 {
		return nil, errors.New("encryption: onion path must have at least one hop")
	}
	for i := range hops {
		if hops[i].PubKey == nil {
			return nil, errors.New("encryption: onion hop has nil public key")
		}
	}

	// Innermost layer: the final destination receives the original payload.
	last := len(hops) - 1
	blob, err := SealHybrid(hops[last].PubKey, onionLayer{IsFinal: true, Inner: finalPayload}.marshalBinary(), nil)
	if err != nil {
		return nil, err
	}

	// Wrap outward: each relay's layer points to the next hop and carries the
	// already-sealed inner blob to forward.
	for i := last - 1; i >= 0; i-- {
		layer := onionLayer{
			IsFinal:  false,
			NextAddr: hops[i+1].Addr,
			NextNode: hops[i+1].NodeID,
			Inner:    blob,
		}
		blob, err = SealHybrid(hops[i].PubKey, layer.marshalBinary(), nil)
		if err != nil {
			return nil, err
		}
	}

	return blob, nil
}

// PeelOnion removes exactly one onion layer using myPriv. It returns the
// recovered layer as an OnionPeel: if IsFinal is true, Inner is the original
// final payload; otherwise Inner is the onion blob to forward to NextAddr. It
// errors if the blob was not sealed to this key or has been tampered with.
func PeelOnion(myPriv *ecdh.PrivateKey, blob []byte) (OnionPeel, error) {
	layerBytes, err := OpenHybrid(myPriv, blob, nil)
	if err != nil {
		return OnionPeel{}, err
	}
	layer, err := unmarshalLayer(layerBytes)
	if err != nil {
		return OnionPeel{}, err
	}
	return OnionPeel{
		IsFinal:  layer.IsFinal,
		NextAddr: layer.NextAddr,
		NextNode: layer.NextNode,
		Inner:    layer.Inner,
	}, nil
}

// KEM abstracts key encapsulation so a PQ KEM (e.g. ML-KEM/Kyber) can replace
// X25519 later.
type KEM interface {
	Encapsulate(peerPub []byte) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(ciphertext []byte) (sharedSecret []byte, err error)
}

// x25519KEM implements KEM over X25519 ECDH. Encapsulation generates an
// ephemeral key pair, performs ECDH against the peer public key, and returns the
// ephemeral public key as the KEM ciphertext alongside the shared secret.
//
// This is the classical building block; ML-KEM (Kyber) is the intended
// post-quantum swap-in and implements the same interface, so callers that
// depend on KEM need not change when the KEM is upgraded.
type x25519KEM struct {
	priv *ecdh.PrivateKey
}

// NewX25519KEM returns a KEM backed by X25519. The provided private key is used
// by Decapsulate; it may be nil if only Encapsulate is needed.
func NewX25519KEM(priv *ecdh.PrivateKey) KEM {
	return &x25519KEM{priv: priv}
}

// Encapsulate generates an ephemeral key pair, performs ECDH against peerPub,
// and returns (ephemeralPub, sharedSecret).
func (k *x25519KEM) Encapsulate(peerPub []byte) (ciphertext, sharedSecret []byte, err error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, nil, err
	}
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ss, err := ephPriv.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	return ephPriv.PublicKey().Bytes(), ss, nil
}

// Decapsulate performs ECDH between the KEM's private key and the encapsulated
// ephemeral public key to recover the shared secret.
func (k *x25519KEM) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if k.priv == nil {
		return nil, errors.New("encryption: x25519KEM has no private key for decapsulation")
	}
	ephPub, err := ecdh.X25519().NewPublicKey(ciphertext)
	if err != nil {
		return nil, err
	}
	return k.priv.ECDH(ephPub)
}
