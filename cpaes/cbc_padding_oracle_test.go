package cpaes

import (
	"encoding/base64"
	"slices"
	"testing"

	"github.com/alesforz/cryptopals/cppad"
)

func TestCbcPaddingOracleAtk(t *testing.T) {
	atkTools := newPaddingOracleAtkTools()

	plainText, err := cbcPaddingOracleAtk(atkTools)
	if err != nil {
		t.Fatalf("attack failed: %s", err)
	}

	// CBC encryption adds its own padding, therefore, the recovered text will be one
	// of the original 10, plus the additional block of padding that the encryption
	// adds. Thus, we remove it.
	unpadded, err := cppad.RemovePKCS7(plainText)
	if err != nil {
		t.Fatalf("attack failed: unpadding recovered plain text: %s", err)
	}

	if !slices.Contains(atkTools.plainTexts, string(unpadded)) {
		t.Fatalf("attack failed: recovered plain text:\n%s\n isn't one of those given by the challenge", unpadded)
	}

	t.Logf("Plain text: %s", unpadded)

	decoded := make([]byte, len(unpadded))
	_, err = base64.StdEncoding.Decode(decoded, unpadded)
	if err != nil {
		t.Fatalf("attack failed: base64 decoding recovered plain text: %s", err)
	}

	t.Logf("Decoded plain text: %s", decoded)
}
