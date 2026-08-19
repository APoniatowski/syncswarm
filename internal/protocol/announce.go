package protocol

import (
	"crypto/ed25519"
	"encoding/binary"
)

// AnnouncePayload is the body of a PacketTypeAnnounce: a node advertising its
// identity and reachability so transport nodes can flood it and build path
// tables. It carries its own Ed25519 Signature over the immutable fields (proof
// that the announcer holds DestHash's private key), independent of the enclosing
// packet's signature — so it remains verifiable no matter how many hops
// re-forward it. HopCount is mutable (incremented per hop) and deliberately
// excluded from the signature.
type AnnouncePayload struct {
	DestHash     string   // hex NodeID; MUST equal DeriveNodeID(SignKey)
	SignKey      []byte   // Ed25519 public key (verifies DestHash and Signature)
	PubKey       []byte   // X25519 public key (so peers can seal/onion toward this node)
	MLKEMPub     []byte   // optional ML-KEM-768 public key (post-quantum sealing)
	Port         uint16   // data port for direct dialing / reachability
	Capabilities []string // e.g. "relay"
	AppData      []byte   // small application hint (opaque here)
	Timestamp    int64    // announcer's Unix-nano clock; signed (freshness/anti-replay)
	Nonce        uint64   // random; makes (DestHash,Nonce) a flood-dedup key
	HopCount     uint8    // MUTABLE, NOT signed: hops travelled so far
	Signature    []byte   // Ed25519 over signedBytes()
}

// PathRequestPayload is the body of a PacketTypePathRequest: a query asking the
// network for a path to DestHash. It makes no identity claim, so it needs no
// inner signature (the enclosing packet is signed by the requester). Nonce makes
// the request dedup-able during flooding; HopCount bounds how far it floods.
type PathRequestPayload struct {
	DestHash string
	Nonce    uint64
	HopCount uint8
}

// signedBytes is the deterministic canonical encoding of every immutable field
// (everything except HopCount and Signature), length-prefixed so no field
// boundary is ambiguous. Both Sign and VerifySig hash exactly these bytes.
func (a *AnnouncePayload) signedBytes() []byte {
	var b []byte
	putLen := func(n int) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(n))
		b = append(b, l[:]...)
	}
	putBytes := func(p []byte) { putLen(len(p)); b = append(b, p...) }
	putStr := func(s string) { putBytes([]byte(s)) }

	putStr(a.DestHash)
	putBytes(a.SignKey)
	putBytes(a.PubKey)
	putBytes(a.MLKEMPub)

	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], a.Port)
	b = append(b, u16[:]...)

	putLen(len(a.Capabilities))
	for _, c := range a.Capabilities {
		putStr(c)
	}
	putBytes(a.AppData)

	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], uint64(a.Timestamp))
	b = append(b, u64[:]...)
	binary.BigEndian.PutUint64(u64[:], a.Nonce)
	b = append(b, u64[:]...)

	return b
}

// Sign sets Signature to an Ed25519 signature over the immutable fields, and
// stamps SignKey from the private key so the announce is self-authenticating.
func (a *AnnouncePayload) Sign(priv ed25519.PrivateKey) {
	if len(priv) != ed25519.PrivateKeySize {
		return
	}
	a.SignKey = priv.Public().(ed25519.PublicKey)
	a.Signature = ed25519.Sign(priv, a.signedBytes())
}

// VerifySig reports whether Signature is a valid Ed25519 signature by SignKey
// over the immutable fields. Callers MUST also check DeriveNodeID(SignKey) ==
// DestHash to bind the identity (key-binding), which VerifyBound does.
func (a *AnnouncePayload) VerifySig() bool {
	if len(a.SignKey) != ed25519.PublicKeySize || len(a.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(a.SignKey), a.signedBytes(), a.Signature)
}

// VerifyBound checks both key-binding (DestHash is derived from SignKey) and the
// signature. A true result means: this announce was authorized by the holder of
// the key that DestHash commits to — it cannot be forged for someone else's ID.
func (a *AnnouncePayload) VerifyBound() bool {
	return a.DestHash != "" && DeriveNodeID(a.SignKey) == a.DestHash && a.VerifySig()
}
