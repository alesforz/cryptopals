package main

import (
	"bytes"
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
	if size >= 256 {
		// can't fit numbers >= 256 in one byte of padding.
		size = 255
	}

	var (
		dataLen = len(data)
		pad     = size - dataLen%size
		padded  = make([]byte, dataLen+pad)
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

type aesOracle func([]byte) ([]byte, error)

// Challenge 12 of set 2.
func ecbEncryptionOracle(secret []byte) (aesOracle, error) {
	key, err := randomBytes(aes.BlockSize, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random AES key: %s", err)
	}

	encOracle := func(plainText []byte) ([]byte, error) {
		padded := make([]byte, len(plainText)+len(secret))
		copy(padded, plainText)
		copy(padded[len(plainText):], secret)

		return encryptAesEcb(padded, key)
	}

	return encOracle, nil
}

// decryptOracleSecret implements a byte-at-a-time decryption attack, aka
// padding oracle attack.
// It decrypts a secret by iteratively guessing each byte of the plain text.
// It first crafts plain texts, then asks the oracle to encrypt them, and
// finally compares the resulting cipher text blocks to the target cipher text.
// This sort of input manipulation allows it to deduce each byte of the secret
// one at a time, thus reconstructing it without needing the encryption key.
// This method exploits the deterministic nature of block ciphers and the
// feedback from the oracle to reveal the hidden data.
// See file example_byte_at_a_time.txt for a visual example of this method.
// Challenge 12 of set 2.
func decryptOracleSecret(encryptionOracle aesOracle) ([]byte, error) {

	var (
		blockSize   = aes.BlockSize
		shortBlocks = make([][]byte, blockSize)
	)
	// craft blocks of known bytes shorter than a full AES block.
	// These will push the unknown byte(s) of the secret into a predictable
	// position within the ciphertext block.
	// For example, if the block is of length 15 (blockSize - 1), the
	// encrypted output will have the first 15 bytes as 'A' and the 16th byte
	// will be the first byte of the secret. With length 14, the encrypted
	// output will have the first 15 bytes as 'A' and the 15th and 16th will be
	// the first 2 bytes of the secret.
	for size := 0; size < blockSize; size++ {
		block := make([]byte, size)
		for i := range block {
			block[i] = 'A'
		}
		shortBlocks[size] = block
	}

	// this will return a cipher text where only the secret has been encrypted
	// (shortBlocks[0] stores an empty block, therefore the oracle will
	// encrypt [{}||secret]).
	// We do this to know the number of blocks we have to decrypt.
	encryptedSecret, err := encryptionOracle(shortBlocks[0])
	if err != nil {
		return nil, err
	}

	var (
		nBlocks = len(encryptedSecret) / blockSize
		secret  = make([]byte, 0, len(encryptedSecret))
	)
	for blockIdx := range nBlocks {
		for size := blockSize - 1; size >= 0; size-- {
			knownBytes := shortBlocks[size]

			// these could be cached, as the encryption of a given short block
			// is always the same cipher text.
			cipherText, err := encryptionOracle(knownBytes)
			if err != nil {
				return secret, err
			}

			var (
				// boundaries of the cipher text block being targeted for
				// decryption.
				start = blockIdx * blockSize
				end   = blockIdx*blockSize + blockSize

				// the cipher text block being targeted for decryption.
				targetBlock = cipherText[start:end]

				// a combination of known bytes, previously
				// decrypted bytes of the secret, and the byte currently being
				// guessed (the +1, which we will brute force in the loop
				// below).
				forged = make([]byte, len(knownBytes)+len(secret)+1)
			)
			copy(forged, knownBytes)
			copy(forged[len(knownBytes):], secret)

			// the "byte-at-a-time" part of the attack.
			// This loop is responsible for guessing the value of the unknown
			// byte of the secret by iterating through all possible byte values
			// (0 to 255) and checking which one produces a ciphertext block
			// that matches the target block.
			// Basically, what we are doing is asking the oracle to encrypt all
			// the possible byte sequences obtained by changing their last byte.
			// For example:
			// oracle("AAAAAAAAAAAAAAAA")
			// oracle("AAAAAAAAAAAAAAAB")
			// oracle("AAAAAAAAAAAAAAAC")
			// oracle("AAAAAAAAAAAAAAAD")
			// .....
			// until the resulting cipher text matches the target block.
			// If the cipher text generated by oracle("AAAAAAAAAAAAAAAD")
			// matches, then 'D' is a byte of the secret.
			// On the next round we will try all possible byte sequences like
			// this:
			// oracle("AAAAAAAAAAAAAADA")
			// oracle("AAAAAAAAAAAAAADB")
			// oracle("AAAAAAAAAAAAAADC")
			// oracle("AAAAAAAAAAAAAADD")
			// .....
			// until the resulting cipher text matches the target block.
			// If the cipher text generated by oracle("AAAAAAAAAAAAAADA")
			// matches, then 'A' is the next byte of the secret.
			// And so on until we decrypted the entire secret.
			for i := range 255 {
				char := byte(i)

				forged[len(forged)-1] = char

				sampleCipherText, err := encryptionOracle(forged)
				if err != nil {
					const formatStr = "trying byte %d (%c): %s"
					return secret, fmt.Errorf(formatStr, i, char, err)
				}

				if bytes.Equal(sampleCipherText[start:end], targetBlock) {
					secret = append(secret, char)
					break
				}
			}
		}
	}

	return secret, nil
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

// delPadPkcs7String is a wrapper of delPadPkcs7 for string data.
func delPadPkcs7String(data string) string {
	return string(delPadPkcs7([]byte(data)))
}

// delPadPkcs7 deletes PKCS#7 padding from data.
// This is a necessary step after decryption of an AES cipher text because AES
// always adds padding before encrypting a plain text.
// If the plaintext is exactly a multiple of the block size, without adding an
// extra block of padding, the decryption process would not be able to
// distinguish whether the last block is part of the plaintext or padding.
// By always adding an additional block of padding, the decrypted message
// clearly indicates the presence of padding bytes, which can be correctly
// removed.
func delPadPkcs7(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	pad := int(data[len(data)-1])
	return data[:len(data)-pad]
}
