package cpxor

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
