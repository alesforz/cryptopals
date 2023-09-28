package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"unicode/utf8"
)

// HexToBase64 converts a hexadecimal string to its Base64 representation.
func HexToBase64(inputHex string) (string, error) {
	decoded, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %s", inputHex)
	}

	return base64.StdEncoding.EncodeToString(decoded), nil
}

// XORHexStrings performs a bitwise XOR operation between two input hexadecimal strings
// of equal length and returns the result as a hexadecimal string.
func XORHexStrings(inputHex1, inputHex2 string) (string, error) {
	// We decode the hex strings to bytes before checking their length, because the byte
	// length might be different from the hex string length due to how hexadecimal
	// encoding works, and direct string length comparison might not always give you the
	// correct assessment.
	decoded1, err := hex.DecodeString(inputHex1)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %s", inputHex1)
	}

	decoded2, err := hex.DecodeString(inputHex2)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %s", inputHex2)
	}

	if len(decoded1) != len(decoded2) {
		return "", fmt.Errorf("decoded bytes are of different lengths, but must be equal")
	}

	// we could reuse decoded1 to save an allocation, but I think creating a separate slice makes
	// the code clearer.
	result := make([]byte, len(decoded1))
	for i := range decoded1 {
		result[i] = decoded1[i] ^ decoded2[i]
	}

	return hex.EncodeToString(result), nil
}

// SingleByteXOR attempts to decrypt a given hex-encoded ciphertext by XORing it against
// each 255 1-byte keys. It then checks which resulting plaintext has character
// frequencies closest to typical English text.
func SingleByteXOR(inputHex string) (string, error) {
	decoded, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %s", inputHex)
	}

	var (
		bestScore  float64
		bestString string
	)
	for char := 0; char <= 255; char++ {
		decrypted := xorWithChar(decoded, byte(char))
		score := computeScore(decrypted)

		if score > bestScore {
			bestScore = score
			bestString = string(decrypted)
		}
	}

	return bestString, nil
}

// RepeatingKeyXOR encrypts the given text using a repeating-key XOR operation.
// The function takes in a plain text and a key as input. Each byte of the text is XORed
// with a corresponding byte from the key. If the length of the text exceeds the length of
// the key, the key is repeated cyclically.
func RepeatingKeyXOR(text string, key []byte) string {
	var (
		result = []byte(text)
		keyLen = len(key)
	)
	for i := range result {
		result[i] ^= key[i%keyLen]
	}

	return hex.EncodeToString(result)
}

// xorWithChar decrypts a byte slice by XORing each byte with the provided character.
func xorWithChar(data []byte, char byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ char
	}
	return result
}

// computeScore calculates and returns a score for the given data based on how closely its
// character frequencies match typical English text. A higher score indicates a closer
// match to English.
func computeScore(data []byte) float64 {
	const uppercaseToLowercaseShift = 'a' - 'A'
	var (
		// we use [utf8.RuneCountInString] instead of len(text) because len(text) returns
		// the number of *bytes*. However, recall that in UTF-8 some characters are
		// encoded using 2 bytes, therefore len(text) could return a number which is
		// higher than the actual number of characters in the text. In contrast
		// [utf8.RuneCountInString] returns the exact number of *characters* in the text,
		// which is what we want here.
		totalChars = float64(utf8.RuneCount(data))
		score      float64
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
	// characters. By normalizing, we adjust for the length of the text, making scores
	// from different text lengths comparable.
	// By doing this, the function calculates the average score per character, giving
	// metric that represents the "English-likeness" of the text on a per-character basis.
	return score / totalChars
}
