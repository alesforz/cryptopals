package cpaes

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"testing"

	"github.com/alesforz/cryptopals/cppad"
)

func TestEncryptECB(t *testing.T) {
	const (
		plainTextStr = "Lorem ipsum dolor sit amet consectetur adipiscin"
		keyStr       = "YELLOW SUBMARINE"
	)

	var (
		plainText = []byte(plainTextStr)
		key       = []byte(keyStr)
	)

	cipherText, err := encryptECB(plainText, key)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	decrypted, err := decryptECB(cipherText, key)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	unpadded := cppad.RemovePKCS7(decrypted)
	if !bytes.Equal(unpadded, plainText) {
		t.Errorf("want: %q\ngot: %q", plainText, decrypted)
	}
}

func TestDecryptECB(t *testing.T) {
	f, err := os.Open("../files/c7.txt")
	if err != nil {
		t.Fatalf("opening file: %s", err)
	}
	defer f.Close()

	decoder := base64.NewDecoder(base64.StdEncoding, f)
	cipherText, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatalf("reading file: %s", err)
	}

	const key = "YELLOW SUBMARINE"
	plainText, err := decryptECB(cipherText, []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(plainText))
}

func TestDetectECB(t *testing.T) {
	f, err := os.Open("../files/c8.txt")
	if err != nil {
		t.Fatalf("opening file: %s", err)
	}
	defer f.Close()

	var (
		s     = bufio.NewScanner(f)
		count int
	)
	for s.Scan() {
		count++

		hexCipherText := s.Text()

		cipherText, err := hex.DecodeString(hexCipherText)
		if err != nil {
			t.Errorf("decoding cipher text %d: %x from hex", count, hexCipherText)
		}
		if detectECB(cipherText) {
			t.Logf("cipher text %d is encrypted using AES ECB", count)
			break
		}
	}
	if err := s.Err(); err != nil {
		t.Errorf("reading input file: %s", err)
	}
}

func TestRandomEncryption(t *testing.T) {
	// we can choose the plaintext. Therefore, to distinguish between the 2
	// encryption modes, we use a plaintext that repeats itself. Remember that ECB
	// produces the same ciphertext blocks given the same plaintext blocks.
	var (
		text               = []byte("Let's encrypt this stuff")
		plainText          = bytes.Repeat(text, 5)
		countECB, countCBC int
	)
	for range 1000 {
		cipherText, err := randomEncryption(plainText)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if detectECB(cipherText) {
			countECB++
		} else {
			countCBC++
		}
	}

	t.Logf("Oracle used ECB %d and CBC %d times\n", countECB, countCBC)
}

func TestDecryptOracleSecret(t *testing.T) {
	// const s = "YELLOW SUBMARINE+RED SUNSHINES=IMMENSE HAPPINESS"
	_, err := ecbEncryptionOracleWithSecret()
	if err != nil {
		t.Fatal(err)
	}

	// decryptedSecret, err := decryptOracleSecret(o)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// t.Log(string(delPadPkcs7(decryptedSecret)))
}
