package pki

import (
	"log"
	"testing"
)

func TestClientEncryptsUsingPublicKeyServerDecryptUsingPrivateKey(t *testing.T) {
	srvKeys, err := New()
	if err != nil {
		log.Fatalf("unexpected error generating keys, err %v", err)
	}

	plainText := "This is a very secret message :)"

	encryptedMessage, err := Encrypt(srvKeys.publicKey, plainText)
	if err != nil {
		log.Fatalf("unexpected error encrypting message, error %v", err)
	}

	plainMessage, err := Decrypt(srvKeys.privateKey, encryptedMessage)
	if err != nil {
		log.Fatalf("unexpected error decrypting message, error %v", err)
	}

	if plainMessage != plainText {
		t.Fatalf("contents do not match, expected %s got %s", plainText, plainMessage)
	}
}

func TestClientSignsEncryptedMessageAndServerValidatesSignature(t *testing.T) {
	clKeys, err := New()
	if err != nil {
		log.Fatalf("unexpected error generating keys, err %v", err)
	}

	plainText := "This is a very secret message :)"

	signature, err := Sign(clKeys.privateKey, plainText)
	if err != nil {
		t.Fatalf("unexpected error signing message, error %v", err)
	}

	err = VerifySign(clKeys.publicKey, signature, plainText)
	if err != nil {
		t.Errorf("could not verify signature: %v", err)
	}
}
