package cpaes

import (
	"fmt"

	"github.com/alesforz/cryptopals/cpxor"
)

// decryptCBC decrypts a cipher text using AES in CBC mode using the given
// key and initialization vector.
// In case of an error during decryption, it returns the error and the plain
// text decrypted up to when the error occurred.
// decryptCBC does not modify the input slices.
// (Solves challenge 10 of set 2)
func decryptCBC(cipherText, key, iv []byte) ([]byte, error) {
	cLen, kLen := len(cipherText), len(key)
	if cLen%kLen != 0 {
		const errStr = "cipher text's length (%d) is not a multiple of the decryption key's length (%d)"
		return nil, fmt.Errorf(errStr, cLen, kLen)
	}

	ivLen := len(iv)
	if ivLen%kLen != 0 {
		const errStr = "initialization vector length %d is not a multiple of the key size %d"
		return nil, fmt.Errorf(errStr, ivLen, kLen)
	}

	decrypter, err := decryptionOracle(key)
	if err != nil {
		return nil, fmt.Errorf("initializing decryption oracle: %s", err)
	}

	var (
		blkSize   = kLen
		nBlocks   = (cLen + blkSize - 1) / blkSize
		plainText = make([]byte, 0, cLen)
	)
	// The first plaintext block, which has no associated previous ciphertext
	// block, is xored with the initialization vector.
	firstBlk := decrypter(cipherText[:blkSize])
	blk, err := cpxor.Blocks(firstBlk, iv)
	if err != nil {
		return nil, fmt.Errorf("xor first plain text block with IV: %s", err)
	}
	plainText = append(plainText, blk...)

	for i := 1; i < nBlocks; i++ {
		var (
			prevBlkStart = (i - 1) * blkSize
			prevBlkEnd   = (i-1)*blkSize + blkSize
			prevBlk      = cipherText[prevBlkStart:prevBlkEnd]

			currBlkStart = i * blkSize
			currBlkEnd   = i*blkSize + blkSize
			currBlk      = decrypter(cipherText[currBlkStart:currBlkEnd])
		)
		plainTextBlock, err := cpxor.Blocks(prevBlk, currBlk)
		if err != nil {
			const errStr = "xor plain text blocks %d and %d: %s"
			return plainText[:prevBlkEnd], fmt.Errorf(errStr, i-1, i, err)
		}
		plainText = append(plainText, plainTextBlock...)
	}

	return plainText, nil
}
