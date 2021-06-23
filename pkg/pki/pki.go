package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

type Key struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

func New() (Key, error) {
	var k Key

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return k, err
	}

	k.publicKey = &privateKey.PublicKey
	k.privateKey = privateKey

	return k, nil
}

func (k Key) PublicKeyToPemString() string {
	return string(
		pem.EncodeToMemory(
			&pem.Block{
				Type: "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(k.publicKey),
			},
		),
	)
}

func (k Key) PrivateKeyToPemString() string {
	return string(
		pem.EncodeToMemory(
			&pem.Block{
				Type: "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(k.privateKey),
			},
		),
	)
}

func LoadPublicKey(publicKeyPath string) (*rsa.PublicKey, error) {
	bytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	return convertBytesToPublicKey(bytes)
}

func Encrypt(publicKey *rsa.PublicKey, plainText []byte) ([]byte, error) {
	cipher, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, plainText, nil)
	if err != nil {
		return nil, err
	}

	return cipherToPemBytes(cipher), nil
}

func LoadPrivateKey(privateKeyPath string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	return convertBytesToPrivateKey(bytes)
}

func Decrypt(privateKey *rsa.PrivateKey, encryptedMessage []byte) (string, error) {
	plainMessage, err := rsa.DecryptOAEP(
		sha512.New(),
		rand.Reader,
		privateKey,
		pemBytesToCipher(encryptedMessage),
		nil,
	)

	return string(plainMessage), err
}

func Sign(privateKey *rsa.PrivateKey, plainText []byte) ([]byte, error) {
	msgHashSum, err := hash(plainText)
	if err != nil {
		return nil, err
	}

	return rsa.SignPSS(rand.Reader,privateKey, crypto.SHA512, msgHashSum, nil)
}

func VerifySign(publicKey *rsa.PublicKey, signature []byte, plainText []byte) error {
	msgHashSum, err := hash(plainText)
	if err != nil {
		return err
	}

	return rsa.VerifyPSS(publicKey, crypto.SHA512, msgHashSum, signature, nil)
}

func hash(plainText []byte) ([]byte, error) {
	msgHash := sha512.New()
	_, err := msgHash.Write(plainText)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)

	return msgHashSum, nil
}

func convertBytesToPublicKey(keyBytes []byte) (*rsa.PublicKey, error) {
	var err error

	block, _ := pem.Decode(keyBytes)
	blockBytes := block.Bytes
	ok := x509.IsEncryptedPEMBlock(block)

	if ok {
		blockBytes, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}

	publicKey, err := x509.ParsePKCS1PublicKey(blockBytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func cipherToPemBytes(cipher []byte) []byte {
	return pem.EncodeToMemory(
			&pem.Block{
				Type: "MESSAGE",
				Bytes: cipher,
			},
		)
}

func convertBytesToPrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	var err error

	block, _ := pem.Decode(keyBytes)
	blockBytes := block.Bytes
	ok := x509.IsEncryptedPEMBlock(block)

	if ok {
		blockBytes, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(blockBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func pemBytesToCipher(encryptedMessage []byte) []byte {
	b, _ := pem.Decode(encryptedMessage)

	return b.Bytes
}