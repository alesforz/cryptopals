package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// hexStrToBase64 converts a hexadecimal string to its Base64 representation.
func hexStrToBase64(hexStr string) (string, error) {
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %s", hexStr)
	}

	return base64.StdEncoding.EncodeToString(hexBytes), nil
}
