package cpaes

import (
	"crypto/aes"
	"fmt"
)

// Oracle is a type that encrypts/decrypts a given plain/cipher text using AES.
// The function does not modify the input slice.
type Oracle func([]byte) []byte

type Block [aes.BlockSize]byte

// encryptionOracle returns an AESOracle which performs the encryption of a byte
// slice with the given key.
// encryptionOracle does not modify the input slice.
func encryptionOracle(key []byte) (Oracle, error) {
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

// decryptionOracle returns an AESOracle which performs the decryption of a byte
// slice with the given key.
// decryptionOracle does not modify the input slice.
func decryptionOracle(key []byte) (Oracle, error) {
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
