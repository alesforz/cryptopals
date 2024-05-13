package main

// padPkcs7 pads the given data to a multiple of size by appending the number of
// bytes of padding to the end of the it.
// For instance, "YELLOW SUBMARINE" (16 bytes) padded to 20 bytes would be:
// "YELLOW SUBMARINE\x04\x04\x04\x04"
// If targetLen >=256, it will pad to size 255.
// Challenge 9 from set 2.
func padPkcs7(data []byte, size int) []byte {
	if size >= 256 {
		// can't fit numbers >= 256 in one byte of padding.
		size = 255
	}

	var (
		dataLen = len(data)
		pad     = size - dataLen%size
		padded  = make([]byte, dataLen+pad)
	)
	copy(padded, data)

	for i := dataLen; i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	return padded
}
