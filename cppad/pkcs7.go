package cppad

// PKCS7 pads the given data to a multiple of size by appending the number of bytes
// of padding to the end of the it.
// For example, "YELLOW SUBMARINE" (16 bytes) padded to 20 bytes is:
// "YELLOW SUBMARINE\x04\x04\x04\x04"
// If targetLen >=256, it will pad to size 255.
// PKCS7 does not modify the input slice; rather, it returns a new slice with the
// padded data.
// (Solves challenge 9 of set 2)
func PKCS7(data []byte, size int) []byte {
	if size >= 256 {
		// can't fit numbers >= 256 in one byte of padding.
		size = 255
	}

	var (
		dLen   = len(data)
		pad    = size - dLen%size
		padded = make([]byte, dLen+pad)
	)
	copy(padded, data)

	for i := dLen; i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	return padded
}
