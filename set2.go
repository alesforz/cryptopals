package main

import (
	"crypto/aes"
	"fmt"
)

// padPKCS7 pads any block to a specific block size by appending the number of
// bytes of padding to the end of the block.
// For instance, "YELLOW SUBMARINE" (16 bytes) padded to 20 bytes would be:
// "YELLOW SUBMARINE\x04\x04\x04\x04"
// If targetLen >=256, it will return a padded block of size 255 bytes.
// Challenge 9 from set 2.
func padPKCS7(block []byte, targetLen int) []byte {
	blockLen := len(block)
	if targetLen <= blockLen {
		// can't pad a block to a size <= than itself.
		return block
	}
	if targetLen >= 256 {
		// can't fit numbers >= 256 in one byte of padding.
		targetLen = 255
	}

	padded := make([]byte, targetLen)
	copy(padded, block)

	pad := byte(targetLen - blockLen)
	for i := blockLen; i < targetLen; i++ {
		padded[i] = pad
	}

	return padded
}

// encryptAESECBString is a wrapper of encryptAESECB for when you have a plain
// text to encrypt and a key to encrypt it as strings.
func encryptAESECBString(plainText, key string) (string, error) {
	cipherText, err := encryptAESECB([]byte(plainText), []byte(key))
	return string(cipherText), err
}

// encryptAESECB encrypts a plain text using AES-128 in ECB mode with the given
// key.
func encryptAESECB(plainText, key []byte) ([]byte, error) {
	var (
		plainTextLen = len(plainText)
		keyLen       = len(key)
	)
	if plainTextLen%keyLen != 0 {
		const formatStr = "plain text length %d is not a multiple of the key size %d"
		return nil, fmt.Errorf(formatStr, plainTextLen, keyLen)
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("instantiating AES ECB cipher: %w", err)
	}

	var (
		blockSize  = aesCipher.BlockSize()
		nBlocks    = (plainTextLen + blockSize - 1) / blockSize
		cipherText = make([]byte, plainTextLen)
	)
	for b := range nBlocks {
		var (
			start = b * blockSize
			end   = start + blockSize
		)
		aesCipher.Encrypt(cipherText[start:end], plainText[start:end])
	}

	return cipherText, nil
}
