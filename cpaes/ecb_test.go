package cpaes

import (
	"encoding/base64"
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
