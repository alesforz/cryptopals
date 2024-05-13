package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// hexToBase64 converts a hexadecimal string to its Base64 representation.
// Challenge 1 of Set 1.
func hexToBase64(inputHex string) (string, error) {
	decoded, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", inputHex)
	}

	return base64.StdEncoding.EncodeToString(decoded), nil
}
