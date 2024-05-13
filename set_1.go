package main

import (
	"crypto/aes"
	"errors"
	"fmt"
	"unicode/utf8"
)

// decryptAesEcbString is a wrapper of decryptAesEcb for when you have a cipher
// text to decrypt and a key to decrypt it as strings.
func decryptAesEcbString(cipherText, key string) (string, error) {
	plainText, err := decryptAesEcb([]byte(cipherText), []byte(key))
	return string(plainText), err
}

// decryptAesEcb decrypts a cipher text encrypted using AES-128 in ECB mode with
// the given key.
// Challenge 7 of Set 1.
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

// isEncryptedAesEcbString is a wrapper around isEncryptedAesEcb for when you
// have a cipher text to decrypt as a string.
func isEncryptedAesEcbString(cipherText string) bool {
	return isEncryptedAesEcb([]byte(cipherText))
}

// isEncryptedAesEcb returns true if the given cipherText was encrypted using
// AES ECB. It leverages the fact that ECB is stateless and deterministic; the
// same 16 byte plaintext block will always produce the same 16 byte
// ciphertext.
// Challenge 8 of Set 1.
func isEncryptedAesEcb(cipherText []byte) bool {
	const blockSize = aes.BlockSize

	cipherTextLen := len(cipherText)
	if cipherTextLen%blockSize != 0 {
		return false
	}

	type block [blockSize]byte

	var (
		nBlocks = (cipherTextLen + blockSize - 1) / blockSize
		set     = make(map[block]struct{}, nBlocks)
	)
	for b := range nBlocks {
		var (
			start = b * blockSize
			end   = start + blockSize

			// get the slice's underlying array
			currBlock = (block)(cipherText[start:end])
		)
		if _, ok := set[currBlock]; ok {
			return true
		}
		set[currBlock] = struct{}{}
	}
	return false
}

// xorBlocks takes two byte slices, b1 and b2, and returns a new byte slice
// containing the result of a byte-wise XOR operation between corresponding
// elements of b1 and b2
func xorBlocks(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("input blocks are of different lengths")
	}

	xored := make([]byte, len(b1))
	for i := range xored {
		xored[i] = b1[i] ^ b2[i]
	}

	return xored, nil
}

// xorWithChar XORs each byte of data with the provided character.
func xorWithChar(data []byte, char byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ char
	}
	return result
}

// computeTextScore calculates and returns a score for the given text based on
// how closely its character frequencies match typical English text. A higher
// score indicates a closer match to valid English.
func computeTextScore(data []byte) float64 {
	const uppercaseToLowercaseShift = 'a' - 'A'
	var (
		// we use [utf8.RuneCountInString] instead of len(text) because
		// len(text) returns the number of *bytes*. However, recall that in
		// UTF-8 some characters are encoded using 2 bytes, therefore len(text)
		// could return a number which is higher than the actual number of
		// characters in the text. In contrast [utf8.RuneCountInString] returns
		// the exact number of *characters* in the text, which is what we want
		// here.
		nChars = float64(utf8.RuneCount(data))
		score  float64
	)

	for _, b := range data {
		if b >= 'A' && b <= 'Z' {
			b += uppercaseToLowercaseShift
		}

		if b >= 'a' && b <= 'z' {
			score += _englishLetterFrequencies[b-'a']
		} else if b == ' ' {
			score += _spaceFrequency
		}
	}

	// Normalization: a longer text will have a higher score because it has more
	// characters. By normalizing, we adjust for the length of the text, making
	// scores from different text lengths comparable.
	// By doing this, the function calculates the average score per character,
	// giving a metric that represents the "English-likeness" of the text on a
	// per-character basis.
	return score / nChars
}
