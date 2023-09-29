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

func TestHexToBase64(t *testing.T) {
	var (
		hexTestStr    = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		base64WantStr = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	gotStr, err := HexToBase64(hexTestStr)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if gotStr != base64WantStr {
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
	} else if gotStr != hexWantStr {
		t.Errorf("got: %s\nwant: %s\n", gotStr, hexWantStr)
	}
}

func TestSingleByteXOR(t *testing.T) {
	hexStr := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipherText, err := decodeTestHex(t, hexStr)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	gotStr, gotKey := SingleByteXOR(cipherText)

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

		gotStr, gotKey := SingleByteXOR(cipherText)

		score := computeScore([]byte(gotStr))
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

func TestRepeatingKeyXOR(t *testing.T) {
	var (
		inputText = []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)

		inputKey       = []byte("ICE")
		wantCipherText = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	)

	gotCipherText := RepeatingKeyXOR(inputText, inputKey)
	if hex.EncodeToString(gotCipherText) != wantCipherText {
		t.Errorf("expected:\n%s\nbut got:\n%s", wantCipherText, gotCipherText)
	}
}

func TestBreakRepeatingKeyXOR(t *testing.T) {
	f, err := os.Open("./files/1_6.txt")
	if err != nil {
		t.Fatalf("opening file: %s", err)
	}
	defer f.Close()

	cipherText, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading file: %s", err)
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(cipherText)))
	bytesWritten, err := base64.StdEncoding.Decode(decoded, cipherText)
	if err != nil {
		t.Fatalf("decoding file contents from base64: %s", err)
	}
	decoded = decoded[:bytesWritten]

	var maxKeySize uint = 40
	plainText, key, err := BreakRepeatingKeyXOR(decoded, maxKeySize)
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

// decodeTestHex attempts to decode the provided hex string into a byte slice.
func decodeTestHex(t *testing.T, hexStr string) ([]byte, error) {
	t.Helper()

	decodedHex, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("malformed hex string '%s': %s", hexStr, err)
	}

	return decodedHex, nil
}
