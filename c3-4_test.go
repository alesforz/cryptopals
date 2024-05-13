package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestSingleByteXOR(t *testing.T) {
	hexStr := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	cipherText, err := decodeTestHex(t, hexStr)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	gotStr, gotKey := singleByteXOR(cipherText)

	t.Logf("Key: %c", gotKey)
	t.Logf("Decoded string: %s", gotStr)

}

// Challenge 4 of Set 1.
func TestSingleByteXORFile(t *testing.T) {
	f, err := os.Open("./files/1_4.txt")
	if err != nil {
		t.Fatalf("opening file: %s", err)
	}
	defer f.Close()

	var (
		s         = bufio.NewScanner(f)
		bestScore float64
		plainText string
		key       byte
	)
	for s.Scan() {
		cipherText, err := decodeTestHex(t, s.Text())
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		gotStr, gotKey := singleByteXOR(cipherText)

		score := computeTextScore([]byte(gotStr))
		if score > bestScore {
			bestScore = score
			plainText = gotStr
			key = gotKey
		}
	}

	if err := s.Err(); err != nil {
		t.Fatalf("parsing file: %s", err)
	}

	t.Logf("Key: %c", key)
	t.Logf("Decoded string: %s", plainText)
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
