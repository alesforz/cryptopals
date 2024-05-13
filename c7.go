package main

import (
	"crypto/aes"
	"fmt"
)

// decryptAesEcb decrypts a cipher text encrypted using AES-128 in ECB mode with
// the given key.
func decryptAesEcb(cipherText, key []byte) ([]byte, error) {
	if len(cipherText)%len(key) != 0 {
		const formatStr = "cipher text's length (%d) is not a multiple of the decryption key's length (%d)"
		return nil, fmt.Errorf(formatStr, len(cipherText), len(key))
	}

	decrypter, err := aesDecrypter(key)
	if err != nil {
		return nil, err
	}

	var (
		blockSize = len(key)
		nBlocks   = (len(cipherText) + blockSize - 1) / blockSize
		plainText = make([]byte, 0, len(cipherText))
	)
	for b := range nBlocks {
		var (
			start = b * blockSize
			end   = start + blockSize
		)
		plainText = append(plainText, decrypter(cipherText[start:end])...)
	}

	return plainText, nil
}

// decryptAesEcbString is a wrapper of decryptAesEcb for when you have a cipher
// text to decrypt and a key to decrypt it as strings.
func decryptAesEcbString(cipherText, key string) (string, error) {
	plainText, err := decryptAesEcb([]byte(cipherText), []byte(key))
	return string(plainText), err
}

// aesDecrypter initializes an AES decryption operation using the provided key.
// It returns an AESECBWorker which performs the decryption of a byte slice
// with the given key.
func aesDecrypter(key []byte) (aesWorker, error) {

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("instantiating AES cipher: %w", err)
	}

	decrypter := func(cipherText []byte) []byte {
		plainText := make([]byte, len(cipherText))
		aesCipher.Decrypt(plainText, cipherText)
		return plainText
	}

	return decrypter, nil
}
