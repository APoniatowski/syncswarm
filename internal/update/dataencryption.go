package update

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
)

func (dataStruct *NetworkUpdateData) encryptUpdateData(key []byte) ([]byte, error) {
	path := "/opt/syncswarm/new/"
	type privPubKey struct {
		priv string
		pub  string
	}
	privPath := path + "private_key.pem"
	pubPath := path + "public_key.pem"
	privKey, err := os.ReadFile(privPath)
	pubKey, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	keyCombo := privPubKey{
		priv: string(privKey),
		pub:  string(pubKey),
	}
	byteKeys, err := json.Marshal(keyCombo)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, byteKeys, nil), nil
}
