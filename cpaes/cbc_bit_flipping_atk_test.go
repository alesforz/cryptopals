package cpaes

import (
	"bytes"
	"crypto/aes"
	"os"
	"testing"

	"github.com/alesforz/cryptopals/cpbytes"
)

func TestCBCBitFlippingAtk(t *testing.T) {
	enc, dec, err := cbcOraclesWithAffix()
	if err != nil {
		t.Fatal(err)
	}

	plainText := cbcBitFlippingAtk(enc, dec)
	if !bytes.Contains(plainText, []byte(";admin=true;")) {
		t.Error("attack unsuccessful")
	}

	cpbytes.PrintBlocks(plainText, aes.BlockSize, os.Stdout)
}

func TestCBCBitFlippingAtk2(t *testing.T) {
	enc, dec, err := cbcOraclesWithAffix()
	if err != nil {
		t.Fatal(err)
	}

	plainText := cbcBitFlippingAtk2(enc, dec)
	if !bytes.Contains(plainText, []byte(";admin=true;")) {
		t.Error("attack unsuccessful")
	}

	cpbytes.PrintBlocks(plainText, aes.BlockSize, os.Stdout)
}

func BenchmarkCBCBitFlippingAtk(b *testing.B) {
	enc, dec, err := cbcOraclesWithAffix()
	if err != nil {
		b.Fatal(err)
	}

	b.Run("CBCBitFlippingAtk", func(b *testing.B) {
		for b.Loop() {
			cbcBitFlippingAtk(enc, dec)
		}
	})

	b.Run("CBCBitFlippingAtk2", func(b *testing.B) {
		for b.Loop() {
			cbcBitFlippingAtk2(enc, dec)
		}
	})

}
