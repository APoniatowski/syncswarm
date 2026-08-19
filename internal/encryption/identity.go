package encryption

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
)

// identityFile is the filename under a node's storage directory that holds its
// persistent Ed25519 identity seed.
const identityFile = "identity.key"

// LoadOrCreateIdentity loads this node's persistent Ed25519 signing identity from
// dir, generating and saving a new one (0600) if none exists. The public key is
// the node's self-authenticating identity; its private key signs the node's
// packets. Persisting it keeps the node's key-bound ID stable across restarts.
func LoadOrCreateIdentity(dir string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	path := filepath.Join(dir, identityFile)
	if seed, err := os.ReadFile(path); err == nil && len(seed) == ed25519.SeedSize {
		priv := ed25519.NewKeyFromSeed(seed)
		return priv, priv.Public().(ed25519.PublicKey), nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, priv.Seed(), 0o600); err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}
