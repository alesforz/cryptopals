package main

import (
	"crypto/aes"
	"fmt"
)

// encryptAesCbc encrypts a plain text using AES in CBC mode using the given
// key and initialization vector.
// In case of an error during encryption, it returns the error and the cipher
// text generated up to when the error occurred.
func encryptAesCbc(plainText, key, iv []byte) ([]byte, error) {
	var (
		ivLen  = len(iv)
		keyLen = len(key)
	)
	if ivLen%keyLen != 0 {
		const formatStr = "initialization vector length %d is not a multiple of the key size %d"
		return nil, fmt.Errorf(formatStr, ivLen, keyLen)
	}

	plainText = padPkcs7(plainText, aes.BlockSize)

	encrypter, err := aesEncrypter(key)
	if err != nil {
		return nil, err
	}

	var (
		plainTextLen = len(plainText)
		blockSize    = aes.BlockSize
		nBlocks      = (plainTextLen + blockSize - 1) / blockSize
		cipherText   = make([]byte, 0, plainTextLen)
	)
	// The first plaintext block, which has no associated previous ciphertext
	// block, is added to the the initialization vector.
	firstBlock, err := xorBlocks(plainText[:blockSize], iv)
	if err != nil {
		return nil, fmt.Errorf("xor first plain text block with IV: %s", err)
	}
	cipherText = append(cipherText, encrypter(firstBlock)...)

	for b := 1; b < nBlocks; b++ {
		var (
			prevBlockStart = (b - 1) * blockSize
			prevBlockEnd   = (b-1)*blockSize + blockSize
			prevBlock      = cipherText[prevBlockStart:prevBlockEnd]

			currBlockStart = b * blockSize
			currBlockEnd   = b*blockSize + blockSize
			currBlock      = plainText[currBlockStart:currBlockEnd]
		)
		cipherTextBlock, err := xorBlocks(prevBlock, currBlock)
		if err != nil {
			const formatStr = "xor plain text blocks %d and %d: %s"
			return cipherText[:prevBlockEnd], fmt.Errorf(formatStr, b-1, b, err)
		}
		cipherText = append(cipherText, encrypter(cipherTextBlock)...)
	}

	return cipherText, nil
}

// decryptAesCbc decrypts a cipher text using AES in CBC mode using the given
// key and initialization vector.
// In case of an error during decryption, it returns the error and the plain
// text decrypted up to when the error occurred.
func decryptAesCbc(cipherText, key, iv []byte) ([]byte, error) {
	var (
		cipherTextLen = len(cipherText)
		keyLen        = len(key)
	)
	if cipherTextLen%keyLen != 0 {
		const formatStr = "cipher text's length (%d) is not a multiple of the decryption key's length (%d)"
		return nil, fmt.Errorf(formatStr, len(cipherText), len(key))
	}

	ivLen := len(iv)
	if ivLen%keyLen != 0 {
		const formatStr = "initialization vector length %d is not a multiple of the key size %d"
		return nil, fmt.Errorf(formatStr, ivLen, keyLen)
	}

	decrypter, err := aesDecrypter(key)
	if err != nil {
		return nil, err
	}

	var (
		blockSize = keyLen
		nBlocks   = (cipherTextLen + blockSize - 1) / blockSize
		plainText = make([]byte, 0, cipherTextLen)
	)
	// The first plaintext block, which has no associated previous ciphertext
	// block, is xored with the initialization vector.
	firstBlock, err := xorBlocks(decrypter(cipherText[:blockSize]), iv)
	if err != nil {
		return nil, fmt.Errorf("xor first plain text block with IV: %s", err)
	}
	plainText = append(plainText, firstBlock...)

	for b := 1; b < nBlocks; b++ {
		var (
			prevBlockStart = (b - 1) * blockSize
			prevBlockEnd   = (b-1)*blockSize + blockSize
			prevBlock      = cipherText[prevBlockStart:prevBlockEnd]

			currBlockStart = b * blockSize
			currBlockEnd   = b*blockSize + blockSize
			currBlock      = decrypter(cipherText[currBlockStart:currBlockEnd])
		)
		plainTextBlock, err := xorBlocks(prevBlock, currBlock)
		if err != nil {
			const formatStr = "xor plain text blocks %d and %d: %s"
			return plainText[:prevBlockEnd], fmt.Errorf(formatStr, b-1, b, err)
		}
		plainText = append(plainText, plainTextBlock...)
	}

	return plainText, nil
}

// aesEncrypter initializes an AES encryption operation in ECB mode using the
// provided key. It returns an aesWorker which performs the encryption of a
// byte slice with the given key.
func aesEncrypter(key []byte) (aesWorker, error) {

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("instantiating AES cipher: %w", err)
	}

	encrypter := func(plainText []byte) []byte {
		cipherText := make([]byte, len(plainText))
		aesCipher.Encrypt(cipherText, plainText)
		return cipherText
	}

	return encrypter, nil
}
