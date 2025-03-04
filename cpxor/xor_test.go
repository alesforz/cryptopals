package cpxor

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/alesforz/cryptopals/cptext"
)

func TestHexStrs(t *testing.T) {
	const (
		hexStr1    = "1c0111001f010100061a024b53535009181c"
		hexStr2    = "686974207468652062756c6c277320657965"
		wantHexStr = "746865206b696420646f6e277420706c6179"
	)

	gotHexStr, err := hexStrs(hexStr1, hexStr2)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if gotHexStr != wantHexStr {
		t.Errorf("got: %s\nwant: %s\n", gotHexStr, wantHexStr)
	}
}

func TestDecryptSingleByteXORCipher(t *testing.T) {
	t.Run("Challenge3", func(t *testing.T) {
		const hexStr = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

		cipherText, err := hex.DecodeString(hexStr)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		gotPlainText, gotKey := decryptSingleByteXORCipher(cipherText)

		t.Logf("Key: %c\n", gotKey)
		t.Logf("Decoded string: %s\n", gotPlainText)
	})

	t.Run("Challenge4", func(t *testing.T) {
		// One of the 60-character strings in this file has been encrypted by
		// single-character XOR. Must find it and print it.
		f, err := os.Open("../files/c4.txt")
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
			cipherText, err := hex.DecodeString(s.Text())
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			gotPlainText, gotKey := decryptSingleByteXORCipher(cipherText)

			score := cptext.ComputeScore([]byte(gotPlainText))
			if score > bestScore {
				bestScore = score
				plainText = gotPlainText
				key = gotKey
			}
		}

		if err := s.Err(); err != nil {
			t.Fatalf("parsing file: %s", err)
		}

		t.Logf("Key: %c\n", key)
		t.Logf("Decoded string: %s\n", plainText)
	})

}

func TestEncryptWithRepeatingKey(t *testing.T) {
	const (
		plainText = `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

		key            = "ICE"
		wantCipherText = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	)

	var (
		plainTextBytes = []byte(plainText)
		keyBytes       = []byte(key)
	)

	gotCipherText := encryptWithRepeatingKey(plainTextBytes, keyBytes)
	if hex.EncodeToString(gotCipherText) != wantCipherText {
		t.Errorf("want: %s\ngot: %s\n", wantCipherText, gotCipherText)
	}
}

func TestBlocks(t *testing.T) {
	t.Run("EqualLength", func(t *testing.T) {
		var (
			b1 = []byte{0x01, 0x02, 0x03}
			b2 = []byte{0x01, 0x02, 0x03}
		)
		got, err := blocks(b1, b2)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		want := []byte{0x00, 0x00, 0x00}
		if !bytes.Equal(got, want) {
			t.Errorf("got: %v\nwant: %v\n", got, want)
		}
	})

	t.Run("DifferentLength", func(t *testing.T) {
		var (
			b1 = []byte{0x01, 0x02, 0x03}
			b2 = []byte{0x01, 0x02}
		)
		_, err := blocks(b1, b2)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		want := "input blocks are of different lengths: 3 and 2"
		if err.Error() != want {
			t.Errorf("got: %s\nwant: %s\n", err.Error(), want)
		}
	})
}
