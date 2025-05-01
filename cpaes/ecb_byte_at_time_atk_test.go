package cpaes

import (
	"testing"
)

func TestByteAtTimeAtk(t *testing.T) {
	oracle, err := ecbEncryptionOracleWithSecret()
	if err != nil {
		t.Fatal(err)
	}

	decryptedSecret, err := byteAtTimeAtk(oracle)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("secret length: ", len(decryptedSecret))
	t.Logf("secret: %s \n", decryptedSecret)
}
