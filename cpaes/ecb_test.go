package cpaes

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

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
