package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func randKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return key
}

func TestAEADRoundTrip(t *testing.T) {
	key := randKey(t)
	sealer, err := NewAEADSealer(key)
	if err != nil {
		t.Fatalf("NewAEADSealer: %v", err)
	}

	plaintext := []byte("fragment payload")
	aad := []byte("transfer-42:index-7")

	ct, err := sealer.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := sealer.Open(ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestAEADFreshNonce(t *testing.T) {
	sealer, err := NewAEADSealer(randKey(t))
	if err != nil {
		t.Fatalf("NewAEADSealer: %v", err)
	}
	pt := []byte("same plaintext")
	c1, _ := sealer.Seal(pt, nil)
	c2, _ := sealer.Seal(pt, nil)
	if bytes.Equal(c1, c2) {
		t.Fatal("two seals of same plaintext produced identical ciphertext (nonce reuse)")
	}
}

func TestAEADWrongKeyFails(t *testing.T) {
	s1, _ := NewAEADSealer(randKey(t))
	s2, _ := NewAEADSealer(randKey(t))

	ct, err := s1.Seal([]byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := s2.Open(ct, []byte("aad")); err == nil {
		t.Fatal("Open with wrong key succeeded, want failure")
	}
}

func TestAEADTamperFails(t *testing.T) {
	sealer, _ := NewAEADSealer(randKey(t))
	ct, err := sealer.Seal([]byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := sealer.Open(ct, []byte("aad")); err == nil {
		t.Fatal("Open of tampered ciphertext succeeded, want failure")
	}
}

func TestAEADWrongAADFails(t *testing.T) {
	sealer, _ := NewAEADSealer(randKey(t))
	ct, err := sealer.Seal([]byte("secret"), []byte("transfer-1:index-0"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := sealer.Open(ct, []byte("transfer-1:index-1")); err == nil {
		t.Fatal("Open with wrong aad succeeded, want failure (replay at wrong position)")
	}
}

func TestAEADRejectsBadKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewAEADSealer(make([]byte, n)); err == nil {
			t.Fatalf("NewAEADSealer accepted %d-byte key, want ErrKeySize", n)
		}
	}
}

func TestAEADShortCiphertext(t *testing.T) {
	sealer, _ := NewAEADSealer(randKey(t))
	if _, err := sealer.Open([]byte{0x00}, nil); err == nil {
		t.Fatal("Open of short ciphertext succeeded, want failure")
	}
}

func TestHybridRoundTrip(t *testing.T) {
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	plaintext := []byte("hybrid fragment payload")
	aad := []byte("transfer-9:index-3")

	ct, err := SealHybrid(pub, plaintext, aad)
	if err != nil {
		t.Fatalf("SealHybrid: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("hybrid ciphertext contains plaintext")
	}

	got, err := OpenHybrid(priv, ct, aad)
	if err != nil {
		t.Fatalf("OpenHybrid: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("hybrid round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestHybridWrongRecipientFails(t *testing.T) {
	_, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	wrongPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	ct, err := SealHybrid(pub, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("SealHybrid: %v", err)
	}
	if _, err := OpenHybrid(wrongPriv, ct, []byte("aad")); err == nil {
		t.Fatal("OpenHybrid with wrong recipient key succeeded, want failure")
	}
}

func TestHybridTamperFails(t *testing.T) {
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	ct, err := SealHybrid(pub, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatalf("SealHybrid: %v", err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := OpenHybrid(priv, ct, []byte("aad")); err == nil {
		t.Fatal("OpenHybrid of tampered ciphertext succeeded, want failure")
	}
}

func newOnionHop(t *testing.T, nodeID, addr string) (OnionHop, *ecdh.PrivateKey) {
	t.Helper()
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	return OnionHop{NodeID: nodeID, Addr: addr, PubKey: pub}, priv
}

func TestBuildPeelOnionThreeHops(t *testing.T) {
	h0, priv0 := newOnionHop(t, "relay-0", "10.0.0.1:9000")
	h1, priv1 := newOnionHop(t, "relay-1", "10.0.0.2:9000")
	h2, priv2 := newOnionHop(t, "dest-2", "10.0.0.3:9000")

	finalPayload := []byte("the secret cargo")
	hops := []OnionHop{h0, h1, h2}

	blob, err := BuildOnion(hops, finalPayload)
	if err != nil {
		t.Fatalf("BuildOnion: %v", err)
	}
	if bytes.Contains(blob, finalPayload) {
		t.Fatal("onion blob contains final payload in the clear")
	}

	// First relay peels the outermost layer, learns hop 1 is next.
	peel0, err := PeelOnion(priv0, blob)
	if err != nil {
		t.Fatalf("PeelOnion hop 0: %v", err)
	}
	if peel0.IsFinal {
		t.Fatal("hop 0 peel reported IsFinal, want relay")
	}
	if peel0.NextAddr != h1.Addr || peel0.NextNode != h1.NodeID {
		t.Fatalf("hop 0 next = (%q,%q), want (%q,%q)", peel0.NextAddr, peel0.NextNode, h1.Addr, h1.NodeID)
	}

	// Second relay peels its layer, learns the destination is next.
	peel1, err := PeelOnion(priv1, peel0.Inner)
	if err != nil {
		t.Fatalf("PeelOnion hop 1: %v", err)
	}
	if peel1.IsFinal {
		t.Fatal("hop 1 peel reported IsFinal, want relay")
	}
	if peel1.NextAddr != h2.Addr || peel1.NextNode != h2.NodeID {
		t.Fatalf("hop 1 next = (%q,%q), want (%q,%q)", peel1.NextAddr, peel1.NextNode, h2.Addr, h2.NodeID)
	}

	// Destination peels the innermost layer and recovers the payload.
	peel2, err := PeelOnion(priv2, peel1.Inner)
	if err != nil {
		t.Fatalf("PeelOnion hop 2: %v", err)
	}
	if !peel2.IsFinal {
		t.Fatal("hop 2 peel not IsFinal, want destination")
	}
	if peel2.NextAddr != "" || peel2.NextNode != "" {
		t.Fatalf("final peel leaked next hop: (%q,%q)", peel2.NextAddr, peel2.NextNode)
	}
	if !bytes.Equal(peel2.Inner, finalPayload) {
		t.Fatalf("final payload mismatch: got %q want %q", peel2.Inner, finalPayload)
	}
}

func TestPeelOnionSingleHop(t *testing.T) {
	h0, priv0 := newOnionHop(t, "dest-0", "10.0.0.9:9000")
	finalPayload := []byte("direct delivery")

	blob, err := BuildOnion([]OnionHop{h0}, finalPayload)
	if err != nil {
		t.Fatalf("BuildOnion: %v", err)
	}
	peel, err := PeelOnion(priv0, blob)
	if err != nil {
		t.Fatalf("PeelOnion: %v", err)
	}
	if !peel.IsFinal {
		t.Fatal("single-hop peel not IsFinal")
	}
	if !bytes.Equal(peel.Inner, finalPayload) {
		t.Fatalf("single-hop payload mismatch: got %q want %q", peel.Inner, finalPayload)
	}
}

func TestPeelOnionWrongKeyFails(t *testing.T) {
	h0, _ := newOnionHop(t, "dest-0", "10.0.0.9:9000")
	wrongPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	blob, err := BuildOnion([]OnionHop{h0}, []byte("payload"))
	if err != nil {
		t.Fatalf("BuildOnion: %v", err)
	}
	if _, err := PeelOnion(wrongPriv, blob); err == nil {
		t.Fatal("PeelOnion with wrong key succeeded, want failure")
	}
}

func TestPeelOnionTamperFails(t *testing.T) {
	h0, priv0 := newOnionHop(t, "dest-0", "10.0.0.9:9000")

	blob, err := BuildOnion([]OnionHop{h0}, []byte("payload"))
	if err != nil {
		t.Fatalf("BuildOnion: %v", err)
	}
	blob[len(blob)-1] ^= 0xff
	if _, err := PeelOnion(priv0, blob); err == nil {
		t.Fatal("PeelOnion of tampered blob succeeded, want failure")
	}
}

func TestBuildOnionRejectsBadInput(t *testing.T) {
	if _, err := BuildOnion(nil, []byte("x")); err == nil {
		t.Fatal("BuildOnion accepted empty path, want failure")
	}
	if _, err := BuildOnion([]OnionHop{{NodeID: "n", Addr: "a"}}, []byte("x")); err == nil {
		t.Fatal("BuildOnion accepted nil-pubkey hop, want failure")
	}
}

func TestKEMEncapsulateDecapsulateAgree(t *testing.T) {
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	kem := NewX25519KEM(priv)
	ct, ssEncap, err := kem.Encapsulate(pub.Bytes())
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	ssDecap, err := kem.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssEncap, ssDecap) {
		t.Fatal("encapsulated and decapsulated shared secrets disagree")
	}
}

func TestKEMDecapsulateWithoutPrivFails(t *testing.T) {
	kem := NewX25519KEM(nil)
	if _, err := kem.Decapsulate(make([]byte, 32)); err == nil {
		t.Fatal("Decapsulate without private key succeeded, want failure")
	}
}
