package main

import (
	"crypto/aes"
	crand "crypto/rand"
	"fmt"
	mrand "math/rand/v2"
)

// padPkcs7 pads the given data to a multiple of size by appending the number of
// bytes of padding to the end of the it.
// For instance, "YELLOW SUBMARINE" (16 bytes) padded to 20 bytes would be:
// "YELLOW SUBMARINE\x04\x04\x04\x04"
// If targetLen >=256, it will pad to size 255.
// Challenge 9 from set 2.
func padPkcs7(data []byte, size int) []byte {
	dataLen := len(data)
	if size >= 256 {
		// can't fit numbers >= 256 in one byte of padding.
		size = 255
	}

	var (
		pad    = size - dataLen%size
		padded = make([]byte, dataLen+pad)
	)
	copy(padded, data)

	for i := dataLen; i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	return padded
}

// encryptAesCbc encrypts a plain text using AES in CBC mode using the given
// key and initialization vector.
// In case of an error during encryption, it returns the error and the cipher
// text generated up to when the error occurred.
// Challenge 10 of Set 2.
func encryptAesCbc(plainText, key, iv []byte) ([]byte, error) {
	var (
		ivLen  = len(iv)
		keyLen = len(key)
	)
	if ivLen%keyLen != 0 {
		const formatStr = "initialization vector length %d is not a multiple of the key size %d"
		return nil, fmt.Errorf(formatStr, ivLen, keyLen)
	}

	plainTextLen := len(plainText)
	if plainTextLen%keyLen != 0 {
		plainText = padPkcs7(plainText, keyLen)
		plainTextLen = len(plainText)
	}

	encrypter, err := aesEncrypter(key)
	if err != nil {
		return nil, err
	}

	var (
		blockSize  = keyLen
		nBlocks    = (plainTextLen + blockSize - 1) / blockSize
		cipherText = make([]byte, 0, plainTextLen)
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
// Challenge 10 of Set 2.
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

// encryptionOracle generates a random AES key and returns an aesWorker that
// encrypts with it.
// Challenge 11 of set 2.
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

// encryptAesEcbString is a wrapper of encryptAesEcb for when you have a plain
// text to encrypt and a key to encrypt it as strings.
func encryptAesEcbString(plainText, key string) (string, error) {
	cipherText, err := encryptAesEcb([]byte(plainText), []byte(key))
	return string(cipherText), err
}

// encryptAesEcb encrypts a plain text using AES-128 in ECB mode with the given
// key.
func encryptAesEcb(plainText, key []byte) ([]byte, error) {
	var (
		plainTextLen = len(plainText)
		keyLen       = len(key)
	)
	if plainTextLen%keyLen != 0 {
		plainText = padPkcs7(plainText, keyLen)
		plainTextLen = len(plainText)
	}

	encrypter, err := aesEncrypter(key)
	if err != nil {
		return nil, err
	}

	var (
		blockSize  = keyLen
		nBlocks    = (plainTextLen + blockSize - 1) / blockSize
		cipherText = make([]byte, 0, plainTextLen)
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

// randomBytes generates returns a slice of size min <= x <= max (chosen
// randomly) filled with random bytes.
func randomBytes(min, max int) ([]byte, error) {
	var (
		nBytes = mrand.IntN(max-min+1) + min
		buf    = make([]byte, nBytes)
	)
	if _, err := crand.Read(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// addRandomNoise prepends and appends random bytes to the given data.
// It does not modify the input data slice.
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
