package cpxor

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"slices"
	"testing"
)

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

	gotCipherText := EncryptWithRepeatingKey(plainTextBytes, keyBytes)
	if hex.EncodeToString(gotCipherText) != wantCipherText {
		t.Errorf("want: %s\ngot: %s\n", wantCipherText, gotCipherText)
	}
}

func TestBreakRepeatingKeyXORCipher(t *testing.T) {
	f, err := os.Open("../files/c6.txt")
	if err != nil {
		t.Fatalf("opening file: %s", err)
	}
	defer f.Close()

	decoder := base64.NewDecoder(base64.StdEncoding, f)
	cipherText, err := io.ReadAll(decoder)
	if err != nil {
		t.Fatalf("reading file: %s", err)
	}

	maxKeySize := 40
	plainText, key, err := breakRepeatingKeyXORCipher(cipherText, maxKeySize)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	t.Logf("Key: %s\n", key)
	t.Logf("Key Size: %d\n", len(key))
	t.Logf("Plain-text:\n%s", plainText)
}

func TestTransposeMatrix(t *testing.T) {
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

	for blockIdx := range nBlocks {
		for byteIdx := range keySize {
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
		t.Errorf("want: %c\ngot: %c\n", want, transposed)
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
		t.Errorf("want: %d, got: %d", wantDistance, gotDistance)
	}
}
