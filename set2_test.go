package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"testing"
)

func TestPadPkcs7(t *testing.T) {
	data := []byte("YELLOW SUBMARINE")

	// pad "YELLOW SUBMARINE" (16 bytes) to 20 bytes
	padded := padPkcs7(data, 20)

	const want = "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(padded) != want {
		t.Errorf("\nwant:\t%q\ngot:\t%q\n", want, string(padded))
	}
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

	if decrypted != plainText {
		const formatStr = "original plain text and decrypted plain text differ:\noriginal:%s\ndecrypted: %s"

		t.Errorf(formatStr, plainText, decrypted)
	}
}

func TestAesCbcEncryption(t *testing.T) {
	var (
		plainText = []byte("Lorem ipsum dolor sit amet consectetur adipiscin")
		key       = []byte("YELLOW SUBMARINE")
		iv        = make([]byte, len(key))
	)
	for i := range iv {
		iv[i] = byte(0)
	}

	cipherText, err := encryptAesCbc(plainText, key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	decrypted, err := decryptAesCbc(cipherText, key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !bytes.Equal(decrypted, plainText) {
		const formatStr = "original plain text and decrypted plain text differ:\noriginal:%s\ndecrypted: %s"

		t.Errorf(formatStr, plainText, decrypted)
	}
}

// Challenge 10 of Set 2.
func TestAesCbcDecryption(t *testing.T) {
	f, err := os.Open("./files/2_10.txt")
	if err != nil {
		t.Fatalf("opening file: %s", err)
	}
	defer f.Close()

	decoder := base64.NewDecoder(base64.StdEncoding, f)
	cipherText, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatalf("reading file: %s", err)
	}

	var (
		key = []byte("YELLOW SUBMARINE")
		iv  = make([]byte, len(key))
	)
	for i := range iv {
		iv[i] = byte(0)
	}

	plainText, err := decryptAesCbc(cipherText, key, iv)
	if err != nil {
		t.Error(err)
	}

	t.Log(string(plainText))
}

// Challenge 11 of Set 2
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
