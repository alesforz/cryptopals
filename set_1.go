package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
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
// each letter of the English alphabet. It then checks which resulting plaintext has
// character frequencies closest to typical English text.
func SingleByteXOR(inputHex string) (string, error) {
	decoded, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %s", inputHex)
	}

	var (
		bestScore  float64 = math.MaxFloat64
		bestString string
	)

	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	for _, char := range alphabet {
		decrypted := xorWithChar(decoded, byte(char))
		score := computeScore(decrypted)

		if score < bestScore {
			bestScore = score
			bestString = string(decrypted)
		}
	}

	return bestString, nil
}

// xorWithChar decrypts a byte slice by XORing each byte with the provided character.
// The function also ensures that all uppercase letters in the resulting slice are
// converted to lowercase for consistent scoring and analysis.
func xorWithChar(data []byte, char byte) []byte {
	const uppercaseToLowercaseShift = 'a' - 'A'

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ char

		// Convert uppercase letter to lowercase
		if result[i] >= 'A' && result[i] <= 'Z' {
			result[i] += uppercaseToLowercaseShift
		}
	}
	return result
}

// computeScore calculates and returns a score for the given data based on how closely its
// character frequencies match typical English text. A lower score indicates a closer
// match to English.
func computeScore(data []byte) float64 {
	var letterFrequencies [26]float64
	totalChars := float64(len(data))

	for _, b := range data {
		if b >= 'a' && b <= 'z' {
			letterFrequencies[b-'a']++
		}
	}

	var score float64
	for i := range letterFrequencies {
		letterFrequencies[i] /= totalChars
		score += math.Abs(_englishLetterFrequencies[i] - letterFrequencies[i])
	}

	return score
}
