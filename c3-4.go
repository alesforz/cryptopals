package main

import "unicode/utf8"

// singleByteXOR attempts to decrypt a given ciphertext by XORing it against
// each 255 1-byte keys. It then checks which resulting plaintext has character
// frequencies closest to typical English text.
func singleByteXOR(cipherText []byte) (string, byte) {
	var (
		bestScore float64
		plainText []byte
		key       byte
	)

	const asciiBytes = 256
	for char := range asciiBytes {
		decrypted := xorWithChar(cipherText, byte(char))
		score := computeTextScore(decrypted)

		if score > bestScore {
			bestScore = score
			plainText = decrypted
			key = byte(char)
		}
	}

	return string(plainText), key
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
