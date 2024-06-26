package main

import (
	"encoding/hex"
	"testing"
)

func TestRepeatingKeyXOR(t *testing.T) {
	var (
		inputText = []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)

		inputKey       = []byte("ICE")
		wantCipherText = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	)

	gotCipherText := repeatingKeyXOR(inputText, inputKey)
	if hex.EncodeToString(gotCipherText) != wantCipherText {
		t.Errorf("expected:\n%s\nbut got:\n%s", wantCipherText, gotCipherText)
	}
}
