package cpaes

import (
	"crypto/aes"
	"fmt"

	"github.com/alesforz/cryptopals/cppad"
	"github.com/alesforz/cryptopals/cpxor"
)

// encryptCBC encrypts a plain text using AES in CBC mode using the given
// key and initialization vector.
// In case of an error during encryption, it returns the error and the cipher
// text generated up to when the error occurred.
// encryptCBC does not modify the input slices.
func encryptCBC(iv, plainText, key []byte) ([]byte, error) {
	ivLen, kLen := len(iv), len(key)
	if ivLen%kLen != 0 {
		const errStr = "iv length (%d) is not a multiple of the key length (%d)"
		return nil, fmt.Errorf(errStr, ivLen, kLen)
	}

	plainText = cppad.PKCS7(plainText, aes.BlockSize)

	encrypter, err := encryptionOracle(key)
	if err != nil {
		return nil, fmt.Errorf("initializing encryption oracle: %s", err)
	}

	var (
		pLen       = len(plainText)
		blkSize    = aes.BlockSize
		nBlocks    = (pLen + blkSize - 1) / blkSize
		cipherText = make([]byte, 0, pLen)
	)
	// The first plaintext block, which has no associated previous ciphertext
	// block, is xored with the initialization vector.
	firstBlk, err := cpxor.Blocks(plainText[:blkSize], iv)
	if err != nil {
		return nil, fmt.Errorf("xor first plain text block with IV: %s", err)
	}

	cipherText = append(cipherText, encrypter(firstBlk)...)

	for i := 1; i < nBlocks; i++ {
		var (
			prevBlkStart = (i - 1) * blkSize
			prevBlkEnd   = prevBlkStart + blkSize
			prevBlk      = cipherText[prevBlkStart:prevBlkEnd]

			currBlkStart = i * blkSize
			currBlkEnd   = currBlkStart + blkSize
			currBlk      = plainText[currBlkStart:currBlkEnd]
		)
		nextBlk, err := cpxor.Blocks(prevBlk, currBlk)
		if err != nil {
			const errStr = "xor plain text blocks %d and %d: %s"
			return cipherText[:prevBlkEnd], fmt.Errorf(errStr, i-1, i, err)
		}

		cipherText = append(cipherText, encrypter(nextBlk)...)
	}

	return cipherText, nil
}

// decryptCBC decrypts a cipher text using AES in CBC mode using the given
// key and initialization vector.
// In case of an error during decryption, it returns the error and the plain
// text decrypted up to when the error occurred.
// decryptCBC does not modify the input slices.
// The plain text that it returns retains the padding. It's up to the caller to
// remove it.
// (Solves challenge 10 of set 2)
func decryptCBC(iv, cipherText, key []byte) ([]byte, error) {
	cLen, kLen := len(cipherText), len(key)
	if cLen%kLen != 0 {
		const errStr = "cipher text's length (%d) is not a multiple of the decryption key's length (%d)"
		return nil, fmt.Errorf(errStr, cLen, kLen)
	}

	ivLen := len(iv)
	if ivLen%kLen != 0 {
		const errStr = "iv length (%d) is not a multiple of the key length (%d)"
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
	firstBlk, err := cpxor.Blocks(decrypter(cipherText[:blkSize]), iv)
	if err != nil {
		return nil, fmt.Errorf("xor first plain text block with IV: %s", err)
	}
	plainText = append(plainText, firstBlk...)

	for i := 1; i < nBlocks; i++ {
		var (
			prevBlkStart = (i - 1) * blkSize
			prevBlkEnd   = prevBlkStart + blkSize
			prevBlk      = cipherText[prevBlkStart:prevBlkEnd]

			currBlkStart = i * blkSize
			currBlkEnd   = currBlkStart + blkSize
			currBlk      = decrypter(cipherText[currBlkStart:currBlkEnd])
		)
		nextBlk, err := cpxor.Blocks(prevBlk, currBlk)
		if err != nil {
			const errStr = "xor plain text blocks %d and %d: %s"
			return plainText[:prevBlkEnd], fmt.Errorf(errStr, i-1, i, err)
		}
		plainText = append(plainText, nextBlk...)
	}

	return plainText, nil
}
