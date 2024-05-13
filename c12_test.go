package main

import (
	"encoding/base64"
	"testing"
)

func TestDecryptOracleSecret(t *testing.T) {
	const secret = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`

	decodedSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("decoding secret suffix: %s", err)
	}

	// const s = "YELLOW SUBMARINE+RED SUNSHINES=IMMENSE HAPPINESS"
	o, err := ecbEncryptionOracle([]byte(decodedSecret))
	if err != nil {
		t.Fatal(err)
	}

	decryptedSecret, err := decryptOracleSecret(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(delPadPkcs7(decryptedSecret)))
}
