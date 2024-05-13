package main

import (
	"bufio"
	"encoding/hex"
	"os"
	"testing"
)

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
