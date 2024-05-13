package main

import (
	"encoding/base64"
	"io"
	"os"
	"slices"
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

func TestHammingDistance(t *testing.T) {
	var (
		inputText1   = "this is a test"
		inputText2   = "wokka wokka!!!"
		wantDistance = 37
	)
	gotDistance, err := hammingDistance([]byte(inputText1), []byte(inputText2))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if gotDistance != wantDistance {
		t.Errorf("expected Hamming distance %d but got %d", wantDistance, gotDistance)
	}
}

func TestTranspose(t *testing.T) {
	var (
		cipherText = []byte{
			'a', 'b', 'c', 'd', 'e',
			'f', 'g', 'h', 'i', 'j',
			'k', 'l', 'm', 'n', 'o',
		}
		keySize       = 3
		cipherTextLen = len(cipherText)
		transposed    = make([]byte, cipherTextLen)
		nBlocks       = (cipherTextLen + keySize - 1) / keySize
	)

	for blockIdx := 0; blockIdx < nBlocks; blockIdx++ {
		for byteIdx := 0; byteIdx < keySize; byteIdx++ {
			var (
				index           = blockIdx*keySize + byteIdx
				transposedIndex = byteIdx*nBlocks + blockIdx
			)
			if index >= cipherTextLen {
				break
			}
			transposed[transposedIndex] = cipherText[index]
		}
	}

	want := []byte{
		'a', 'd', 'g', 'j', 'm',
		'b', 'e', 'h', 'k', 'n',
		'c', 'f', 'i', 'l', 'o',
	}

	if !slices.Equal(transposed, want) {
		t.Errorf("want: %c, but got %c", want, transposed)
	}
}
