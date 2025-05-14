package cpaes

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"testing"

	"github.com/alesforz/cryptopals/cppad"
)

func TestEncryptCBC(t *testing.T) {
	var (
		plainText = []byte("Lorem ipsum dolor sit amet consectetur adipiscin")
		key       = []byte("YELLOW SUBMARINE")
		iv        = make([]byte, len(key))
	)

	cipherText, err := encryptCBC(plainText, key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	decrypted, err := decryptCBC(cipherText, key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	unpadded, err := cppad.RemovePKCS7(decrypted)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !bytes.Equal(unpadded, plainText) {
		t.Errorf("want: %q\ngot: %q\n", plainText, decrypted)
	}
}

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
	plainText, err := decryptCBC(cipherText, key, iv)
	if err != nil {
		t.Error(err)
	}

	t.Log(string(plainText))
}
