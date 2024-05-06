package main

// padPKCS7 pads any block to a specific block size by appending the number of
// bytes of padding to the end of the block.
// For instance, "YELLOW SUBMARINE" (16 bytes) padded to 20 bytes would be:
// "YELLOW SUBMARINE\x04\x04\x04\x04"
// If targetLen >=256, it will return a padded block of size 255 bytes.
// Challenge 9 from set 2.
func padPKCS7(block []byte, targetLen int) []byte {
	blockLen := len(block)
	if targetLen <= blockLen {
		// can't pad a block to a size <= than itself.
		return block
	}
	if targetLen >= 256 {
		// can't fit numbers >= 256 in one byte of padding.
		targetLen = 255
	}

	padded := make([]byte, targetLen)
	copy(padded, block)

	pad := byte(targetLen - blockLen)
	for i := blockLen; i < targetLen; i++ {
		padded[i] = pad
	}

	return padded
}
