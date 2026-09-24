package encryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// TestSeal_ContentIsNotRepeatableButLengthIs pins the two halves of what a
// passive recorder can and cannot do with a short, guessable message.
//
// The intuition worth correcting is that a short known plaintext like "OK" is
// somehow easier to attack, or that sealing it twice would reveal a pattern. It
// does not: every seal draws a fresh ephemeral X25519 keypair, so the AEAD key is
// unique per message, and the GCM nonce is fresh on top of that. Two seals of the
// same bytes share nothing.
//
// What *is* perfectly repeatable is the length. A 2-byte plaintext yields the same
// ciphertext size every time, so a short message is identifiable by size even
// though its content is not. That is why padding — not more encryption — is the
// defence against correlating short, predictable traffic.
func TestSeal_ContentIsNotRepeatableButLengthIs(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()

	first, err := SealHybrid(pub, []byte("OK"), nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SealHybrid(pub, []byte("OK"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("identical plaintext produced identical ciphertext: the seal is " +
			"deterministic, and repeated messages would be trivially linkable")
	}

	// Not merely different — unrelated. Any shared structure at a fixed offset
	// would be a linkable fingerprint across messages.
	matching := 0
	for i := range first {
		if i < len(second) && first[i] == second[i] {
			matching++
		}
	}
	if matching > len(first)/8 {
		t.Fatalf("%d of %d bytes match at the same offsets; the two seals share "+
			"structure a recorder could fingerprint", matching, len(first))
	}

	// The length, by contrast, carries the information padding exists to hide.
	if len(first) != len(second) {
		t.Fatalf("seal length varies (%d vs %d); this test's premise needs revisiting",
			len(first), len(second))
	}
	long, err := SealHybrid(pub, bytes.Repeat([]byte("x"), 200), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(long) <= len(first) {
		t.Fatal("a longer plaintext did not produce a longer seal; expected the " +
			"length leak this test documents")
	}

	// Decryption still works, so none of the above costs correctness.
	opened, err := OpenHybrid(priv, first, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, []byte("OK")) {
		t.Fatalf("round trip returned %q", opened)
	}
}
