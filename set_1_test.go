package main

import (
	"bufio"
	"os"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	var (
		hexTestStr    = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		base64WantStr = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	gotStr, err := HexToBase64(hexTestStr)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if gotStr != base64WantStr {
		t.Errorf("got: %s\nwant: %s\n", gotStr, base64WantStr)
	}
}

func TestXORHexStrings(t *testing.T) {
	var (
		hexStr1    = "1c0111001f010100061a024b53535009181c"
		hexStr2    = "686974207468652062756c6c277320657965"
		hexWantStr = "746865206b696420646f6e277420706c6179"
	)

	gotStr, err := XORHexStrings(hexStr1, hexStr2)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if gotStr != hexWantStr {
		t.Errorf("got: %s\nwant: %s\n", gotStr, hexWantStr)
	}
}

func TestSingleByteXOR(t *testing.T) {
	hexStr := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	gotStr, err := SingleByteXOR(hexStr)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	t.Logf("Decoded string: %s", gotStr)
}

func TestSingleByteXORFile(t *testing.T) {
	f, err := os.Open("./files/1_4.txt")
	if err != nil {
		t.Fatalf("opening file: %s", err)
	}
	defer f.Close()

	var (
		s          = bufio.NewScanner(f)
		bestScore  float64
		bestString string
	)
	for s.Scan() {
		gotStr, err := SingleByteXOR(s.Text())
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}

		score := computeScore([]byte(gotStr))
		if score > bestScore {
			bestScore = score
			bestString = gotStr
		}
	}

	if err := s.Err(); err != nil {
		t.Fatalf("parsing file: %s", err)
	}

	t.Logf("Decoded string: %s", bestString)
}
