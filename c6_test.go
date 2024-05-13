package main

import (
	"encoding/base64"
	"io"
	"os"
	"testing"
)

func TestBreakRepeatingKeyXOR(t *testing.T) {
	f, err := os.Open("./files/1_6.txt")
	if err != nil {
		t.Fatalf("opening file: %s", err)
	}
	defer f.Close()

	decoder := base64.NewDecoder(base64.StdEncoding, f)
	cipherText, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatalf("reading file: %s", err)
	}

	var maxKeySize = 40
	plainText, key, err := breakRepeatingKeyXOR(cipherText, maxKeySize)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	t.Logf("Key: %s", key)
	t.Logf("Key Size: %d", len(key))
	t.Logf("Plain-text:\n%s", plainText)
}
