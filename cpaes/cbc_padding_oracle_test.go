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

	encoded := base64.StdEncoding.EncodeToString(unpadded)

	if !slices.Contains(atkTools.plainTexts, encoded) {
		t.Fatalf("attack failed: recovered plain text:\n%q\n isn't one of those given by the challenge", unpadded)
	}
	t.Logf("Plain text: %s", unpadded)
}
