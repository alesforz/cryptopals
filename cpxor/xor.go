package cpxor

import (
	"encoding/hex"
	"fmt"

	"github.com/alesforz/cryptopals/cptext"
)

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

	xored, err := blocks(b1, b2)
	if err != nil {
		return "", fmt.Errorf("can't xor given strings: %s", err)
	}

	return hex.EncodeToString(xored), nil
}

// decryptSingleByteXORCipher attempts to decrypt a given ciphertext by XORing it
// against each 255 1-byte keys. It then checks which resulting plaintext has
// character frequencies closest to typical English text.
// decryptSingleByteXORCipher returns the decrypted plaintext as a string and the key
// used to decrypt it.
// decryptSingleByteXORCipher does not modify the input slice.
// (Solves challenges 3 and 4 of set 1).
func decryptSingleByteXORCipher(cipherText []byte) (string, byte) {
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

	return string(plainText), key
}

// encryptWithRepeatingKey encrypts the given text using a repeating-key XOR
// operation.
// Each byte of the text is XORed with a corresponding byte from the key. If the
// length of the text exceeds the length of the key, the key is repeated cyclically.
// For example, if the text is "HELLO" and the key is "AB", the effective key
// used for encryption would be "ABABA".
// It returns the encrypted text as a new byte slice.
// encryptWithRepeatingKey does not modify the input slices.
// (Solves challenge 5 of set 1).
func encryptWithRepeatingKey(plainText, key []byte) []byte {
	var (
		cipherText = make([]byte, len(plainText))
		keyLen     = len(key)
	)
	for i := range plainText {
		cipherText[i] = plainText[i] ^ key[i%keyLen]
	}

	return cipherText
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
// This function is an alias for encryptWithChar, as XORing twice with the same
// character results in the original data.
func decryptWithChar(data []byte, char byte) []byte {
	return encryptWithChar(data, char)
}
