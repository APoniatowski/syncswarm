package encryption

import (
	"bytes"
	"testing"
)

// TestHybridSealerRoundTripAndConfidentiality: a payload sealed to a recipient's
// public key is openable only with that recipient's private key.
func TestHybridSealerRoundTripAndConfidentiality(t *testing.T) {
	aPriv, aPub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bPriv, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sender := NewHybridSealer(aPub, nil) // seals to A
	aad := []byte("transfer-context")
	ct, err := sender.Seal([]byte("top secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("top secret")) {
		t.Fatal("ciphertext leaks plaintext")
	}

	// The intended recipient opens it.
	if pt, err := NewHybridSealer(nil, aPriv).Open(ct, aad); err != nil || string(pt) != "top secret" {
		t.Fatalf("recipient could not open: %v (%q)", err, pt)
	}
	// A different key cannot.
	if _, err := NewHybridSealer(nil, bPriv).Open(ct, aad); err == nil {
		t.Fatal("a non-recipient key must not open the ciphertext")
	}
	// Wrong AAD cannot.
	if _, err := NewHybridSealer(nil, aPriv).Open(ct, []byte("wrong")); err == nil {
		t.Fatal("wrong AAD must fail")
	}
	// A sealer without a public key cannot seal; without a private key cannot open.
	if _, err := NewHybridSealer(nil, aPriv).Seal([]byte("x"), nil); err == nil {
		t.Fatal("seal without recipient pub must fail")
	}
	if _, err := NewHybridSealer(aPub, nil).Open(ct, aad); err == nil {
		t.Fatal("open without private key must fail")
	}
}
