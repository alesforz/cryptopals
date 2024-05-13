package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"
	"testing"
)

// Challenge 7 of Set 1.
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

// Challenge 8 of set 1.
func TestDetectAesEcb(t *testing.T) {
	f, err := os.Open("./files/1_8.txt")
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

		cipherText := s.Text()

		decoded, err := hex.DecodeString(cipherText)
		if err != nil {
			t.Errorf("decoding cipher text %d: %x from hex", count, cipherText)
		}
		if isEncryptedAesEcb(decoded) {
			t.Logf("cipher text %d is encrypted using AES ECB", count)
			break
		}
	}
	if err := s.Err(); err != nil {
		t.Errorf("reading input file: %s", err)
	}
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

// decodeTestHex attempts to decode the provided hex string into a byte slice.
func decodeTestHex(t *testing.T, hexStr string) ([]byte, error) {
	t.Helper()

	decodedHex, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("malformed hex string '%s': %s", hexStr, err)
	}

	return decodedHex, nil
}
