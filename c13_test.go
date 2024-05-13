package main

import (
	"crypto/aes"
	"testing"
)

func TestCreateAdminUser(t *testing.T) {
	key, err := randomBytes(aes.BlockSize, aes.BlockSize)
	if err != nil {
		t.Fatalf("generating random AES key: %s", err)
	}

	encryptionOracle := func(email []byte) ([]byte, error) {
		userProfile, err := profileFor(string(email))
		if err != nil {
			return nil, err
		}
		return encryptAesEcb([]byte(userProfile), key)
	}

	decryptionOracle := func(plainText []byte) ([]byte, error) {
		return decryptAesEcb(plainText, key)
	}

	admin, err := createAdminProfile(encryptionOracle, decryptionOracle)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(admin)
}
