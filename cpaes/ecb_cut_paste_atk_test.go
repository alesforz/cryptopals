package cpaes

import (
	"crypto/aes"
	"maps"
	"testing"

	"github.com/alesforz/cryptopals/cpbytes"
)

func TestCutAndPasteAtk(t *testing.T) {
	key, err := cpbytes.Random(aes.BlockSize, aes.BlockSize)
	if err != nil {
		t.Fatalf("generating random AES key: %s", err)
	}

	var (
		encOracle = func(plainText []byte) []byte {
			cipherText, err := encryptECB(plainText, key)
			if err != nil {
				t.Fatalf("encrypting: %s", err)
			}
			return cipherText
		}

		decOracle = func(cipherText []byte) []byte {
			plainText, err := decryptECB(cipherText, key)
			if err != nil {
				t.Fatalf("decrypting: %s", err)
			}
			return plainText
		}
	)
	adminCookie := cutAndPasteAtk(encOracle, decOracle)
	t.Logf("admin profile: %s\n", adminCookie)

	wantProfile := map[string]string{
		"email": "foooo@bar.com",
		"uid":   "10",
		"role":  "admin",
	}
	adminProfile := parseProfile(adminCookie)
	if !maps.Equal(wantProfile, adminProfile) {
		formatStr := "unexpected admin profile:\nwant: %v\ngot: %v\n"
		t.Fatalf(formatStr, wantProfile, adminProfile)
	}

}
