package cpxor

import (
	"encoding/hex"
	"fmt"
)

// hexStrs performs a bitwise XOR operation between two hexadecimal strings of equal
// length and returns the result as a new hexadecimal string.
func hexStrs(s1, s2 string) (string, error) {
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

	xored, err := blocks(b1, b2)
	if err != nil {
		return "", fmt.Errorf("can't xor given strings: %s", err)
	}

	return hex.EncodeToString(xored), nil
}

// blocks takes two byte slices of equal length, b1 and b2, and returns a new
// byte slice containing the result of a byte-wise XOR operation between
// corresponding elements of b1 and b2.
// blocks does not modify the input slices.
func blocks(b1, b2 []byte) ([]byte, error) {
	lb1, lb2 := len(b1), len(b2)
	if lb1 != lb2 {
		errStr := "input blocks are of different lengths: %d and %d"
		return nil, fmt.Errorf(errStr, lb1, lb2)
	}

	xored := make([]byte, lb1)
	for i := range xored {
		xored[i] = b1[i] ^ b2[i]
	}

	return xored, nil
}
