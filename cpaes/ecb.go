package cpaes

import (
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
		blockSize = kLen
		nBlocks   = (cLen + blockSize - 1) / blockSize
		plainText = make([]byte, 0, cLen)
	)
	for i := range nBlocks {
		var (
			blkStart     = i * blockSize
			blkEnd       = blkStart + blockSize
			decryptedBlk = decrypter(cipherText[blkStart:blkEnd])
		)
		plainText = append(plainText, decryptedBlk...)
	}

	return plainText, nil
}
