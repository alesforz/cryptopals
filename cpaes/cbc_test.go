package cpaes

import (
	"encoding/base64"
	"io"
	"os"
	"testing"
)

func TestDecryptCBC(t *testing.T) {
	f, err := os.Open("../files/c10.txt")
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

	plainText, err := decryptCBC(cipherText, key, iv)
	if err != nil {
		t.Error(err)
	}

	t.Log(string(plainText))
}
