package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
