package cpaes

import (
	"crypto/aes"
	"fmt"
	"math/rand/v2"

	"github.com/alesforz/cryptopals/cpbytes"
	"github.com/alesforz/cryptopals/cppad"
)

// encryptECB encrypts a plain text using AES-128 in ECB mode with the given key.
// It pads the plain text using PKCS#7 padding to ensure its length is a multiple
// of the block size.
// The function does not modify the input slices.
func encryptECB(plainText, key []byte) ([]byte, error) {
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
	for i := range nBlocks {
		var (
			start        = i * blkSize
			end          = start + blkSize
			encryptedBlk = encrypter(plainText[start:end])
		)
		cipherText = append(cipherText, encryptedBlk...)
	}

	return cipherText, nil
}

// decryptECB decrypts a cipher text encrypted using AES-128 in ECB mode with the
// given key.
// The function does not modify the input slices.
// (Solves challenge 7 of set 1)
func decryptECB(cipherText, key []byte) ([]byte, error) {
	cLen, kLen := len(cipherText), len(key)
	if cLen%kLen != 0 {
		const errStr = "cipher text's length (%d) is not a multiple of the decryption key's length (%d)"
		return nil, fmt.Errorf(errStr, cLen, kLen)
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
	for i := range nBlocks {
		var (
			blkStart     = i * blkSize
			blkEnd       = blkStart + blkSize
			decryptedBlk = decrypter(cipherText[blkStart:blkEnd])
		)
		plainText = append(plainText, decryptedBlk...)
	}

	return plainText, nil
}

// detectECB returns true if the given cipherText was encrypted using AES ECB.
// It leverages the fact that ECB is stateless and deterministic; the same 16 byte
// plaintext block will always produce the same 16 byte ciphertext.
// detectECB does not modify the input slice.
// (Solves challenge 8 of set 1)
func detectECB(cipherText []byte) bool {
	const blkSize = aes.BlockSize

	cLen := len(cipherText)
	if cLen%blkSize != 0 {
		return false
	}

	var (
		nBlocks = (cLen + blkSize - 1) / blkSize
		blkSet  = make(map[Block]struct{}, nBlocks)
	)
	for i := range nBlocks {
		var (
			blkStart = i * blkSize
			blkEnd   = blkStart + blkSize

			// get the slice's underlying array
			currBlk = (Block)(cipherText[blkStart:blkEnd])
		)
		if _, ok := blkSet[currBlk]; ok {
			// if we have already seen this block, then the cipherText was encrypted
			// using ECB.
			return true
		}
		blkSet[currBlk] = struct{}{}
	}
	return false
}

// randomEncryption chooses to encrypt using AES ECB 1/2 the time, and using AES CBC
// the other half (using a random IV).
// The function does not modify the input slice.
// (Solves challenge 11 of set 2)
func randomEncryption(plainText []byte) ([]byte, error) {
	padded, err := cpbytes.AddNoise(plainText, 5, 10)
	if err != nil {
		return nil, fmt.Errorf("adding noise to plain text: %s", err)
	}

	key, err := cpbytes.Random(aes.BlockSize, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random AES key: %s", err)
	}

	if coinFlip := rand.IntN(2); coinFlip == 0 {
		return encryptECB(padded, key)
	}

	iv, err := cpbytes.Random(aes.BlockSize, aes.BlockSize)
	if err != nil {
		const formatStr = "generating random IV for AES CBC encryption: %s"
		return nil, fmt.Errorf(formatStr, err)
	}

	return encryptCBC(padded, key, iv)
}
