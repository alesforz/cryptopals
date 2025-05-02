package cphex

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// ToBase64 converts a hexadecimal string to its Base64 representation.
// (Solves challenge 1 of set 1).
func ToBase64(h string) (string, error) {
	decoded, err := hex.DecodeString(h)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", h)
	}

	return base64.StdEncoding.EncodeToString(decoded), nil
}
