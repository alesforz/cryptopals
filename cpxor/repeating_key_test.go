package cpxor

import (
	"encoding/hex"
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

	gotCipherText := encryptWithRepeatingKey(plainTextBytes, keyBytes)
	if hex.EncodeToString(gotCipherText) != wantCipherText {
		t.Errorf("want: %s\ngot: %s\n", wantCipherText, gotCipherText)
	}
}
