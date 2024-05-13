package main

// singleByteXOR attempts to decrypt a given ciphertext by XORing it against
// each 255 1-byte keys. It then checks which resulting plaintext has character
// frequencies closest to typical English text.
func singleByteXOR(cipherText []byte) (string, byte) {
	var (
		bestScore float64
		plainText []byte
		key       byte
	)

	const asciiBytes = 256
	for char := range asciiBytes {
		decrypted := xorWithChar(cipherText, byte(char))
		score := computeTextScore(decrypted)

		if score > bestScore {
			bestScore = score
			plainText = decrypted
			key = byte(char)
		}
	}

	return string(plainText), key
}
