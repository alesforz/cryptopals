package main

import (
	"testing"
)

func TestPadPKCS7(t *testing.T) {
	data := []byte("YELLOW SUBMARINE")

	// pad "YELLOW SUBMARINE" (16 bytes) to 20 bytes
	padded := padPKCS7(data, 20)

	const want = "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(padded) != want {
		t.Errorf("\nwant:\t%q\ngot:\t%q\n", want, string(padded))
	}
}

func TestAESECBEncryption(t *testing.T) {
	var (
		plainText = "Lorem ipsum dolor sit amet consectetur adipiscin"
		key       = "YELLOW SUBMARINE"
	)

	cipherText, err := encryptAESECBString(plainText, key)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	decrypted, err := decryptAESECBString(cipherText, key)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if decrypted != plainText {
		const formatStr = "original plain text and decrypted plain text differ:\noriginal:%s\ndecrypted: %s"

		t.Errorf(formatStr, plainText, decrypted)
	}
}
