package cpaes

import (
	"crypto/aes"
	"fmt"
)

// AESOracle is a type that encrypts/decrypts a given plain/cipher text using AES.
// The function does not modify the input slice.
type AESOracle func([]byte) []byte

type Block [aes.BlockSize]byte

// encryptionOracle initializes an AES encryption operation using the provided key.
// It returns an AESOracle which performs the encryption of a byte slice with the
// given key using AES.
// encryptionOracle does not modify the input slice.
func encryptionOracle(key []byte) (AESOracle, error) {
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
