package cpxor

import (
	"encoding/hex"
	"fmt"

	"github.com/alesforz/cryptopals/cptext"
)

// Blocks takes two byte slices of equal length, b1 and b2, and returns a new
// byte slice containing the result of a byte-wise XOR operation between
// corresponding elements of b1 and b2.
// Blocks does not modify the input slices.
func Blocks(b1, b2 []byte) ([]byte, error) {
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

// hexStrs performs a bitwise XOR operation between two hexadecimal strings of equal
// length and returns the result as a new hexadecimal string.
// (Solves challenge 2 of set 1).
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

	xored, err := Blocks(b1, b2)
	if err != nil {
		return "", fmt.Errorf("can't xor given strings: %s", err)
	}

	return hex.EncodeToString(xored), nil
}

// decryptSingleByteXORCipher attempts to decrypt a given ciphertext by XORing it
// against each 255 1-byte keys. It then checks which resulting plaintext has
// character frequencies closest to typical English text.
// decryptSingleByteXORCipher returns the decrypted plaintext and the key used to
// decrypt it.
// decryptSingleByteXORCipher does not modify the input slice.
// (Solves challenges 3 and 4 of set 1).
func decryptSingleByteXORCipher(cipherText []byte) ([]byte, byte) {
	const asciiBytes = 256
	var (
		bestScore float64
		plainText []byte
		key       byte
	)
	for char := range asciiBytes {
		decrypted := decryptWithChar(cipherText, byte(char))
		score := cptext.ComputeScore(decrypted)

		if score > bestScore {
			bestScore = score
			plainText = decrypted
			key = byte(char)
		}
	}

	return plainText, key
}

// encryptWithChar XORs each byte of the input data slice with the provided
// character and returns a new byte slice with the result.
// encryptWithChar does not modify the input slice.
func encryptWithChar(data []byte, char byte) []byte {
	xored := make([]byte, len(data))
	for i, b := range data {
		xored[i] = b ^ char
	}
	return xored
}

// decryptWithChar XORs each byte of the input data slice with the provided
// character and returns a new byte slice with the result.
// decryptWithChar does not modify the input slice.
// This function is an alias for encryptWithChar (since XORing a byte twice with the
// same key byte results in the original byte) added for better readability
// in the context of wanting to decrypt a ciphertext.
func decryptWithChar(data []byte, char byte) []byte {
	return encryptWithChar(data, char)
}
