package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
)

func TestSealHybridPQRoundTripAndConfidentiality(t *testing.T) {
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqDecap, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}

	aad := []byte("ctx")
	ct, err := SealHybridPQ(xPriv.PublicKey(), pqDecap.EncapsulationKey(), []byte("post-quantum secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("post-quantum secret")) {
		t.Fatal("ciphertext leaks plaintext")
	}

	// The intended recipient (both keys) opens it.
	pt, err := OpenHybridPQ(xPriv, pqDecap, ct, aad)
	if err != nil || string(pt) != "post-quantum secret" {
		t.Fatalf("recipient could not open: %v (%q)", err, pt)
	}

	// A different X25519 key (but correct ML-KEM) cannot: the hybrid needs BOTH.
	otherX, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := OpenHybridPQ(otherX, pqDecap, ct, aad); err == nil {
		t.Fatal("wrong X25519 key must not open (hybrid binds both secrets)")
	}
	// A different ML-KEM key (but correct X25519) cannot either.
	otherPQ, _ := mlkem.GenerateKey768()
	if _, err := OpenHybridPQ(xPriv, otherPQ, ct, aad); err == nil {
		t.Fatal("wrong ML-KEM key must not open")
	}
	// Wrong AAD fails.
	if _, err := OpenHybridPQ(xPriv, pqDecap, ct, []byte("nope")); err == nil {
		t.Fatal("wrong AAD must fail")
	}
}

// TestMLKEMCiphertextSize pins the ML-KEM-768 ciphertext length this code assumes.
func TestMLKEMCiphertextSize(t *testing.T) {
	dk, _ := mlkem.GenerateKey768()
	_, ct := dk.EncapsulationKey().Encapsulate()
	if len(ct) != mlkem768CiphertextSize {
		t.Fatalf("ML-KEM-768 ciphertext = %d bytes, code assumes %d", len(ct), mlkem768CiphertextSize)
	}
}
