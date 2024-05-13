package main

import "crypto/aes"

// isEncryptedAesEcb returns true if the given cipherText was encrypted using
// AES ECB. It leverages the fact that ECB is stateless and deterministic; the
// same 16 byte plaintext block will always produce the same 16 byte
// ciphertext.
func isEncryptedAesEcb(cipherText []byte) bool {
	const blockSize = aes.BlockSize

	cipherTextLen := len(cipherText)
	if cipherTextLen%blockSize != 0 {
		return false
	}

	type block [blockSize]byte

	var (
		nBlocks = (cipherTextLen + blockSize - 1) / blockSize
		set     = make(map[block]struct{}, nBlocks)
	)
	for b := range nBlocks {
		var (
			start = b * blockSize
			end   = start + blockSize

			// get the slice's underlying array
			currBlock = (block)(cipherText[start:end])
		)
		if _, ok := set[currBlock]; ok {
			return true
		}
		set[currBlock] = struct{}{}
	}
	return false
}
