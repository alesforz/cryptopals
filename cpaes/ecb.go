package cpaes

import (
	"crypto/aes"
	"fmt"
)

// decryptECB decrypts a cipher text encrypted using AES-128 in ECB mode with the
// given key.
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
