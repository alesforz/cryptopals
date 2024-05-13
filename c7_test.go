package main

import (
	"encoding/base64"
	"io"
	"os"
	"testing"
)

func TestDecryptAesEcb(t *testing.T) {
	f, err := os.Open("./files/1_7.txt")
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
	plainText, err := decryptAesEcb(cipherText, []byte(key))
	if err != nil {
		t.Error(err)
	}

	t.Log(string(plainText))
}
