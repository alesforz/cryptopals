package cpaes

import (
	"encoding/base64"
	"testing"
)

// Solves challenge 18 of set 3
func TestDecryptCTR(t *testing.T) {
	var (
		cipherTextBase64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
		key              = []byte("YELLOW SUBMARINE")
		nonce            = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	)
	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		t.Fatalf("Failed to decode cipher text from base64: %v", err)
	}

	plainText, err := ctr(cipherText, key, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt CTR: %v", err)
	}
	t.Log("Decrypted plaintext:\n", string(plainText))
}
