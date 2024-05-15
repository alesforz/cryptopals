package main

import (
	"crypto/aes"
	"net/url"
	"testing"
)

func TestProfileFor(t *testing.T) {
	const email = "foo@bar.com"

	if got, err := profileFor(email); err != nil {
		t.Errorf("unexpected error: %s", err)
	} else {
		// it encodes the '@' char as '%40'
		t.Log(got)
	}
}

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

	adminOracle := func(cipherText []byte) (bool, error) {
		const (
			roleKey   = "role"
			adminRole = "admin"
		)
		plainText, err := decryptAesEcb(cipherText, key)
		if err != nil {
			return false, err
		}

		adminProfile := delPadPkcs7(plainText)
		v, err := url.ParseQuery(string(adminProfile))
		if err != nil {
			return false, err
		}

		t.Log(string(adminProfile))

		return v.Get(roleKey) == adminRole, nil
	}

	isAdmin, err := createAdminProfile(encryptionOracle, adminOracle)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !isAdmin {
		t.Fatalf("Profile is not admin")
	}
}
