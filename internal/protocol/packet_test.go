package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

// sk returns a deterministic Ed25519 test key.
func sk() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestDeriveNodeIDBinding(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	id := DeriveNodeID(pub)
	if len(id) != 32 {
		t.Fatalf("node id length = %d, want 32", len(id))
	}
	p := NewPacket(PacketTypeData, []byte("x"), "", id)
	p.SourceNode = id
	p.Sign(priv)
	if p.SignerID() != id {
		t.Fatalf("SignerID %q != derived %q", p.SignerID(), id)
	}
	if DeriveNodeID(nil) != "" {
		t.Fatal("DeriveNodeID(nil) should be empty")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	p := NewPacket(PacketTypeData, []byte("hello world"), "ANY", "node-b")
	p.SourceNode = "node-a"
	p.ChunkNumber = 3
	p.TotalChunks = 10

	p.Sign(sk())

	if len(p.Signature) == 0 {
		t.Fatal("Sign did not populate Signature")
	}
	if !p.Verify() {
		t.Fatal("Verify failed on a freshly signed packet")
	}
}

func TestVerifyFailsOnTamper(t *testing.T) {
	base := func() *Packet {
		p := NewPacket(PacketTypeData, []byte("payload"), "grp", "dst")
		p.SourceNode = "src"
		p.ChunkNumber = 1
		p.TotalChunks = 2
		p.PayloadSize = uint32(len("payload"))
		p.Sign(sk())
		return p
	}

	t.Run("payload", func(t *testing.T) {
		p := base()
		p.Payload = []byte("PAYLOAD")
		if p.Verify() {
			t.Fatal("Verify should fail after payload tamper")
		}
	})

	t.Run("chunk-number", func(t *testing.T) {
		p := base()
		p.ChunkNumber = 99
		if p.Verify() {
			t.Fatal("Verify should fail after ChunkNumber tamper")
		}
	})

	t.Run("source-node", func(t *testing.T) {
		p := base()
		p.SourceNode = "attacker"
		if p.Verify() {
			t.Fatal("Verify should fail after SourceNode tamper")
		}
	})

	t.Run("type", func(t *testing.T) {
		p := base()
		p.Type = PacketTypeAcknowledgement
		if p.Verify() {
			t.Fatal("Verify should fail after Type tamper")
		}
	})

	t.Run("signature", func(t *testing.T) {
		p := base()
		p.Signature[0] ^= 0xff
		if p.Verify() {
			t.Fatal("Verify should fail after Signature tamper")
		}
	})

	t.Run("unsigned", func(t *testing.T) {
		p := NewPacket(PacketTypeData, []byte("x"), "g", "d")
		if p.Verify() {
			t.Fatal("Verify should fail on an unsigned packet")
		}
	})
}

func TestSignatureStableForSamePacket(t *testing.T) {
	p1 := &Packet{
		Type:        PacketTypeData,
		ID:          [32]byte{1, 2, 3},
		SourceNode:  "src",
		DestGroup:   "grp",
		DestNode:    "dst",
		ChunkNumber: 4,
		TotalChunks: 8,
		PayloadSize: 3,
		Payload:     []byte("abc"),
	}
	p2 := *p1

	p1.Sign(sk())
	p2.Sign(sk())

	if !bytes.Equal(p1.Signature, p2.Signature) {
		t.Fatal("signatures differ for identical canonical fields")
	}
}

func TestNewPacketTypeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  PacketType
		want PacketType
	}{
		{"Data", PacketTypeData, 0},
		{"Discovery", PacketTypeDiscovery, 1},
		{"LatencyCheck", PacketTypeLatencyCheck, 2},
		{"LatencyReply", PacketTypeLatencyReply, 3},
		{"Acknowledgement", PacketTypeAcknowledgement, 4},
		{"PeerExchange", PacketTypePeerExchange, 5},
		{"Relay", PacketTypeRelay, 6},
	}

	seen := make(map[PacketType]string)
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
		if prev, ok := seen[c.got]; ok {
			t.Errorf("value %d collides: %s and %s", c.got, prev, c.name)
		}
		seen[c.got] = c.name
	}
}

func TestPeerExchangePacketRoundTrip(t *testing.T) {
	orig := PeerExchangePayload{
		Peers: []PeerInfo{
			{
				NodeID:       "node-a",
				Address:      "10.0.0.1:9000",
				PubKey:       []byte{0x01, 0x02, 0x03, 0x04},
				Port:         9000,
				Capabilities: []string{"relay"},
				LastSeen:     time.Unix(1700000000, 0).UTC(),
			},
			{
				NodeID:       "node-b",
				Address:      "10.0.0.2:9001",
				PubKey:       []byte{0xaa, 0xbb, 0xcc},
				Port:         9001,
				Capabilities: nil,
				LastSeen:     time.Unix(1700000123, 0).UTC(),
			},
		},
	}

	body, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal PeerExchangePayload: %v", err)
	}

	p := NewPacket(PacketTypePeerExchange, body, "ANY", "")
	p.SourceNode = "node-a"
	p.Sign(sk())

	if !p.Verify() {
		t.Fatal("Verify failed on a freshly signed PeerExchange packet")
	}

	var decoded PeerExchangePayload
	if err := json.Unmarshal(p.Payload, &decoded); err != nil {
		t.Fatalf("unmarshal PeerExchangePayload: %v", err)
	}
	if len(decoded.Peers) != len(orig.Peers) {
		t.Fatalf("peer count = %d, want %d", len(decoded.Peers), len(orig.Peers))
	}
	for i := range orig.Peers {
		if decoded.Peers[i].NodeID != orig.Peers[i].NodeID {
			t.Errorf("peer %d NodeID = %q, want %q", i, decoded.Peers[i].NodeID, orig.Peers[i].NodeID)
		}
		if !bytes.Equal(decoded.Peers[i].PubKey, orig.Peers[i].PubKey) {
			t.Errorf("peer %d PubKey = %x, want %x", i, decoded.Peers[i].PubKey, orig.Peers[i].PubKey)
		}
		if decoded.Peers[i].Port != orig.Peers[i].Port {
			t.Errorf("peer %d Port = %d, want %d", i, decoded.Peers[i].Port, orig.Peers[i].Port)
		}
		if !decoded.Peers[i].LastSeen.Equal(orig.Peers[i].LastSeen) {
			t.Errorf("peer %d LastSeen = %v, want %v", i, decoded.Peers[i].LastSeen, orig.Peers[i].LastSeen)
		}
	}

	// Tampering with the payload must invalidate the signature.
	p.Payload[0] ^= 0xff
	if p.Verify() {
		t.Fatal("Verify should fail after PeerExchange payload tamper")
	}
}

func TestRelayPacketSignVerify(t *testing.T) {
	onion := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33}

	p := NewPacket(PacketTypeRelay, onion, "ANY", "next-hop")
	p.SourceNode = "node-a"
	p.Sign(sk())

	if !p.Verify() {
		t.Fatal("Verify failed on a freshly signed Relay packet")
	}

	p.Payload[0] ^= 0xff
	if p.Verify() {
		t.Fatal("Verify should fail after Relay onion blob tamper")
	}
}

func TestDiscoveryPayloadPubKeyRoundTrip(t *testing.T) {
	orig := DiscoveryPayload{
		NodeID:       "node-a",
		Version:      "1.0",
		Capabilities: []string{"relay", "storage"},
		Port:         9000,
		Nonce:        42,
		PubKey:       []byte{0x10, 0x20, 0x30, 0x40, 0x50},
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal DiscoveryPayload: %v", err)
	}

	var decoded DiscoveryPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal DiscoveryPayload: %v", err)
	}
	if !bytes.Equal(decoded.PubKey, orig.PubKey) {
		t.Fatalf("PubKey = %x, want %x", decoded.PubKey, orig.PubKey)
	}
	if decoded.NodeID != orig.NodeID || decoded.Port != orig.Port || decoded.Nonce != orig.Nonce {
		t.Fatalf("scalar fields did not round-trip: %+v", decoded)
	}
}

func TestHexID(t *testing.T) {
	var id [32]byte
	for i := range id {
		id[i] = byte(i)
	}
	got := HexID(id)
	if len(got) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(got))
	}
	if got[:4] != "0001" {
		t.Fatalf("unexpected hex prefix: %q", got[:4])
	}
}

func TestBinaryCodecRoundTrip(t *testing.T) {
	p := NewPacket(PacketTypeData, []byte("payload-bytes"), "grp", "dst")
	p.SourceNode = "src"
	p.ChunkNumber = 7
	p.TotalChunks = 9
	p.DataShards = 4
	p.ParityShards = 2
	p.OriginalLen = 12345
	p.Variable = true
	p.Decoy = false
	p.ReplyBlock = []byte{0xaa, 0xbb}
	p.Pad = []byte{1, 2, 3}
	p.Sign(sk())

	// Wire frame round-trips through Read/WritePacket and preserves the signature.
	var buf bytes.Buffer
	if err := WritePacket(&buf, p); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPacket(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != p.Type || got.ID != p.ID || got.SourceNode != p.SourceNode ||
		got.ChunkNumber != p.ChunkNumber || got.TotalChunks != p.TotalChunks ||
		got.DataShards != p.DataShards || got.ParityShards != p.ParityShards ||
		got.OriginalLen != p.OriginalLen || got.Variable != p.Variable ||
		string(got.Payload) != string(p.Payload) || string(got.ReplyBlock) != string(p.ReplyBlock) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, p)
	}
	if !got.Verify() {
		t.Fatal("signature must survive the binary round-trip")
	}
	// Tampering after decode still fails verification.
	got.Payload[0] ^= 0xff
	if got.Verify() {
		t.Fatal("tamper should fail verification")
	}
	// A truncated frame is a clean error, not a panic.
	if _, err := ReadPacket(bytes.NewReader([]byte{0, 0, 0, 5, 1, 2})); err == nil {
		t.Fatal("expected error on truncated frame")
	}
}
