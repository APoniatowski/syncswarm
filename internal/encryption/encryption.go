package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func init() {
	path := "/opt/syncswarm/"
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		err := os.MkdirAll(path+"new", 0755)
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func GenerateKeys(bitSize int) error {
	path := "/opt/syncswarm/new/"
	// double check if the dir is there
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			return err
		}
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return err
	}

	privateKeyFile, err := os.Create(path + "private_key.pem")
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	_, err = privateKeyFile.Write(privateKeyPEM)
	if err != nil {
		return err
	}

	publicKeyFile, err := os.Create(path + "public_key.pem")
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

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
	_, err = publicKeyFile.Write(publicKeyPEM)
	if err != nil {
		return err
	}

	return nil
}
