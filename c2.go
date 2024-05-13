package main

import (
	"encoding/hex"
	"fmt"
)

// xorHexStrings performs a bitwise XOR operation between two input hexadecimal
// strings of equal length and returns the result as a hexadecimal string.
func xorHexStrings(s1, s2 string) (string, error) {
	// We decode the hex strings to bytes before checking their length, because
	// the byte length might be different from the hex string length due to how
	// hexadecimal encoding works, and direct string length comparison might
	// not always give you the correct assessment.
	b1, err := hex.DecodeString(s1)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", s1)
	}

	b2, err := hex.DecodeString(s2)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", s2)
	}

	xored, err := xorBlocks(b1, b2)
	if err != nil {
		return "", fmt.Errorf("can't xor given strings: %s", err)
	}

	return hex.EncodeToString(xored), nil
}
