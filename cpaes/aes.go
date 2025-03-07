package cpaes

import (
	"crypto/aes"
	"fmt"
)

// AESOracle is a type that encrypts/decrypts a given plain/cipher text using AES.
// The function does not modify the input slice.
type AESOracle func([]byte) []byte

// decryptionOracle initializes an AES decryption operation using the provided key.
// It returns an AESOracle which performs the decryption of a byte slice with the
// given key using AES.
// decryptionOracle does not modify the input slice.
func decryptionOracle(key []byte) (AESOracle, error) {
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
