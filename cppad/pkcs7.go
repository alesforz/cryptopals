package cppad

// PKCS7 pads the given data to a multiple of size by appending the number of bytes
// of padding to the end of the it.
// For example, "YELLOW SUBMARINE" (16 bytes) padded to 20 bytes is:
// "YELLOW SUBMARINE\x04\x04\x04\x04"
// PKCS7 does not modify the input slice; rather, it returns a new slice with the
// padded data.
// (Solves challenge 9 of set 2)
func PKCS7(data []byte, size uint8) []byte {
	var (
		dLen   = len(data)
		pad    = int(size) - dLen%int(size)
		padded = make([]byte, dLen+pad)
	)
	copy(padded, data)

	for i := dLen; i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	return padded
}

// RemovePKCS7 deletes PKCS7 padding from data.
// This is a necessary step after decryption of an AES cipher text because AES
// always adds padding before encrypting a plain text.
// If the plaintext is exactly a multiple of the block size, without adding an
// extra block of padding, the decryption process would not be able to
// distinguish whether the last block is part of the plaintext or padding.
// By always adding an additional block of padding, the decrypted message
// clearly indicates the presence of padding bytes, which can be correctly
// removed.
// RemovePKCS7 does not modify the input slice; rather, it returns a new slice
// with the padding removed.
func RemovePKCS7(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	var (
		pad      = int(data[len(data)-1])
		unpadded = make([]byte, len(data)-pad)
	)
	// copy copies the minimum of len(unpadded) and len(data) bytes from data to
	// unpadded, therefore it copies only the unpadded bytes.
	copy(unpadded, data)

	return unpadded
}
