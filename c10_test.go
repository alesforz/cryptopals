package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"testing"
)

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

	if !bytes.Equal(delPadPkcs7(decrypted), plainText) {
		const formatStr = "original plain text and decrypted plain text differ:\noriginal: %q\ndecrypted: %q"

		t.Errorf(formatStr, plainText, decrypted)
	}
}

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
