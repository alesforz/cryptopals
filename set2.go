package main

import (
	"crypto/aes"
	"fmt"
)

// padPkcs7 pads any block to a specific block size by appending the number of
// bytes of padding to the end of the block.
// For instance, "YELLOW SUBMARINE" (16 bytes) padded to 20 bytes would be:
// "YELLOW SUBMARINE\x04\x04\x04\x04"
// If targetLen >=256, it will return a padded block of size 255 bytes.
// Challenge 9 from set 2.
func padPkcs7(block []byte, targetLen int) []byte {
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

	encrypter, err := aesEncrypter(plainText, key)
	if err != nil {
		return nil, err
	}

	var (
		blockSize    = keyLen
		plainTextLen = len(plainText)
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
			prevBlock = plainText[(b-1)*blockSize : (b-1)*blockSize+blockSize]
			currBlock = plainText[b*blockSize : b*blockSize+blockSize]
		)
		block, err := xorBlocks(prevBlock, currBlock)
		if err != nil {
			const formatStr = "xor plain text blocks %d and %d: %s"
			return cipherText, fmt.Errorf(formatStr, b-1, b, err)
		}
		cipherText = append(cipherText, encrypter(block)...)
	}

	return cipherText, nil
}

// encryptAesEcbString is a wrapper of encryptAesEcb for when you have a plain
// text to encrypt and a key to encrypt it as strings.
func encryptAesEcbString(plainText, key string) (string, error) {
	cipherText, err := encryptAesEcb([]byte(plainText), []byte(key))
	return string(cipherText), err
}

// encryptAesEcb encrypts a plain text using AES-128 in ECB mode with the given
// key.
func encryptAesEcb(plainText, key []byte) ([]byte, error) {

	encrypter, err := aesEncrypter(plainText, key)
	if err != nil {
		return nil, err
	}

	var (
		blockSize    = len(key)
		plainTextLen = len(plainText)
		nBlocks      = (plainTextLen + blockSize - 1) / blockSize
		cipherText   = make([]byte, 0, plainTextLen)
	)
	for b := range nBlocks {
		var (
			start = b * blockSize
			end   = start + blockSize
		)
		cipherText = append(cipherText, encrypter(plainText[start:end])...)
	}

	return cipherText, nil
}

// aesWorker defines a type that performs an AES encryption/decryption
// operation on the given data, and returns the result of that operation.
type aesWorker func([]byte) []byte

// aesEncrypter initializes an AES encryption operation in ECB mode using the
// provided key. It returns an aesWorker which performs the encryption of a
// byte slice with the given key.
func aesEncrypter(plainText, key []byte) (aesWorker, error) {
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

	encrypter := func(plainText []byte) []byte {
		cipherText := make([]byte, len(plainText))
		aesCipher.Encrypt(cipherText, plainText)
		return cipherText
	}

	return encrypter, nil
}

// aesDecrypter initializes an AES decryption operation using the provided key.
// It returns an AESECBWorker which performs the decryption of a byte slice
// with the given key.
func aesDecrypter(cipherText, key []byte) (aesWorker, error) {
	var (
		cipherTextLen = len(cipherText)
		keyLen        = len(key)
	)
	if cipherTextLen%keyLen != 0 {
		const formatStr = "cipher text length %d is not a multiple of the key size %d"
		return nil, fmt.Errorf(formatStr, cipherTextLen, keyLen)
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("instantiating AES ECB cipher: %w", err)
	}

	decrypter := func(cipherText []byte) []byte {
		plainText := make([]byte, len(cipherText))
		aesCipher.Decrypt(plainText, cipherText)
		return plainText
	}

	return decrypter, nil
}
