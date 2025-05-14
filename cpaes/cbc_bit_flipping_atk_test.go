package cpaes

import (
	"bytes"
	"crypto/aes"
	"testing"
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

	printBlocks(t, plainText, aes.BlockSize)
}

func printBlocks(t *testing.T, bb []byte, blkSize uint) {
	nBlks := (uint(len(bb)) + blkSize - 1) / blkSize

	for i := range nBlks {
		var (
			blkStart = i * blkSize
			blkEnd   = blkStart + blkSize
			blk      = bb[blkStart:blkEnd]
		)
		t.Logf("%-*v\t%s\n", 3, blk, blk)
	}
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
