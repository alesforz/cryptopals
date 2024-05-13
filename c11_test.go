package main

import (
	"bytes"
	"testing"
)

func TestEncryptionOracle(t *testing.T) {
	// we can choose the plaintext so, to distinguish between the 2 encryption
	// modes, we use a plaintext that repeats itself. Remember that ECB
	// produces the same ciphertext blocks given the same plaintext blocks.
	var (
		text               = []byte("Let's encrypt this stuff")
		plainText          = bytes.Repeat(text, 5)
		countECB, countCBC int
	)
	for i := 0; i < 1000; i++ {
		cipherText, err := encryptionOracle(plainText)
		if err != nil {
			t.Fatalf("oracle returned: %s", err)
		}
		if isEncryptedAesEcb(cipherText) {
			countECB++
		} else {
			countCBC++
		}
	}

	t.Logf("Oracle used ECB %d and CBC %d times\n", countECB, countCBC)
}

func TestAesEcbEncryption(t *testing.T) {
	var (
		plainText = "Lorem ipsum dolor sit amet consectetur adipiscin"
		key       = "YELLOW SUBMARINE"
	)

	cipherText, err := encryptAesEcbString(plainText, key)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	decrypted, err := decryptAesEcbString(cipherText, key)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if delPadPkcs7String(decrypted) != plainText {
		const formatStr = "original plain text and decrypted plain text differ:\noriginal: %q\ndecrypted: %q"

		t.Errorf(formatStr, plainText, decrypted)
	}
}
