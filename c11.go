package main

import (
	"crypto/aes"
	"fmt"
	mrand "math/rand/v2"
)

// encryptionOracle generates a random AES key and returns an aesWorker that
// encrypts with it.
func encryptionOracle(plainText []byte) ([]byte, error) {
	padded, err := addRandomNoise(plainText)
	if err != nil {
		return nil, fmt.Errorf("secretly adding noise to plain text: %s", err)
	}

	key, err := randomBytes(aes.BlockSize, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random AES key: %s", err)
	}

	if coinFlip := mrand.IntN(2); coinFlip == 0 {
		return encryptAesEcb(padded, key)
	}

	iv, err := randomBytes(aes.BlockSize, aes.BlockSize)
	if err != nil {
		const formatStr = "generating random IV for AES CBC encryption: %s"
		return nil, fmt.Errorf(formatStr, err)
	}

	return encryptAesCbc(padded, key, iv)
}

// encryptAesEcb encrypts a plain text using AES-128 in ECB mode with the given
// key.
func encryptAesEcb(plainText, key []byte) ([]byte, error) {
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
	for b := range nBlocks {
		var (
			start = b * blockSize
			end   = start + blockSize
		)
		cipherText = append(cipherText, encrypter(plainText[start:end])...)
	}

	return cipherText, nil
}

// encryptAesEcbString is a wrapper of encryptAesEcb for when you have a plain
// text to encrypt and a key to encrypt it as strings.
func encryptAesEcbString(plainText, key string) (string, error) {
	cipherText, err := encryptAesEcb([]byte(plainText), []byte(key))
	return string(cipherText), err
}

// addRandomNoise prepends and appends random bytes to the given data.
// It does not modify the forged data slice.
func addRandomNoise(data []byte) ([]byte, error) {
	prefix, err := randomBytes(5, 10)
	if err != nil {
		return nil, err
	}
	suffix, err := randomBytes(5, 10)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, len(prefix)+len(data)+len(suffix))
	copy(buf, prefix)
	copy(buf[len(prefix):], data)
	copy(buf[len(prefix)+len(data):], suffix)

	return buf, nil
}
