package main

import (
	"encoding/hex"
	"errors"
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
