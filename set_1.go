package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sync"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"
)

// hexToBase64 converts a hexadecimal string to its Base64 representation.
// Challenge 1 of Set 1.
func hexToBase64(inputHex string) (string, error) {
	decoded, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", inputHex)
	}

	return base64.StdEncoding.EncodeToString(decoded), nil
}

// xorHexStrings performs a bitwise XOR operation between two input hexadecimal
// strings of equal length and returns the result as a hexadecimal string.
// Challenge 2 of Set 1.
func xorHexStrings(inputHex1, inputHex2 string) (string, error) {
	// We decode the hex strings to bytes before checking their length, because
	// the byte length might be different from the hex string length due to how
	// hexadecimal encoding works, and direct string length comparison might
	// not always give you the correct assessment.
	decoded1, err := hex.DecodeString(inputHex1)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", inputHex1)
	}

	decoded2, err := hex.DecodeString(inputHex2)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", inputHex2)
	}

	if len(decoded1) != len(decoded2) {
		err := errors.New("decoded bytes are of different lengths")
		return "", err
	}

	// we could reuse decoded1 to save an allocation, but I think creating a
	// separate slice makes the code clearer.
	result := make([]byte, len(decoded1))
	for i := range decoded1 {
		result[i] = decoded1[i] ^ decoded2[i]
	}

	return hex.EncodeToString(result), nil
}

// singleByteXOR attempts to decrypt a given ciphertext by XORing it against
// each 255 1-byte keys. It then checks which resulting plaintext has character
// frequencies closest to typical English text.
// Challenge 3 and 4 of Set 1.
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

// repeatingKeyXOR encrypts the given text using a repeating-key XOR operation.
// The function takes in a plain text and a key as input. Each byte of the text
// is XORed with a corresponding byte from the key. If the length of the text
// exceeds the length of the key, the key is repeated cyclically.
// For example, if the text is "HELLO" and the key is "AB", the effective key
// used for encryption would be "ABABA".
// Challenge 5 of Set 1.
func repeatingKeyXOR(plainText, key []byte) []byte {
	var (
		cipherText = make([]byte, len(plainText))
		keyLen     = len(key)
	)
	for i := range plainText {
		cipherText[i] = plainText[i] ^ key[i%keyLen]
	}

	return cipherText
}

// breakRepeatingKeyXOR:
// 1. Determines the probable key size using statistical analysis.
// 2. Transposes the cipher text by aligning bytes encrypted with the same key
// byte.
// 3. Recovers the decryption key with frequency analysis on each transposed
// block to determine the key's byte used to encrypt that particular block.
// 4. Decrypts the cipher text
// Returns the decrypted text, the key used to encrypt/decrypt it, and an error
// (if any).
// Challenge 6 of Set 1.
func breakRepeatingKeyXOR(
	cipherText []byte,
	maxKeySize int,
) (string, string, error) {

	keySize, err := estimateKeySize(cipherText, maxKeySize)
	if err != nil {
		return "", "", fmt.Errorf("breaking repeating key XOR: %s", err)
	}

	var (
		cipherTextLen = len(cipherText)
		transposed    = make([]byte, cipherTextLen)

		// if the cipher-text length isn't a multiple of the key's size, there
		// will be one last block of length < keySize which we need to consider.
		// By adding (keySize - 1) before the division, we're "rounding up" the
		// number of blocks, thus giving us the correct number of blocks even
		// if there's a remainder.
		nBlocks = (cipherTextLen + keySize - 1) / keySize
	)

	// Loop through all indices of the input cipherText.
	// Now that we have an estimation of the key's size, we break the
	// ciphertext into blocks of keySize length and transpose them.
	// The ciphertext is a sequence of bytes where each byte is encrypted using
	// a corresponding byte of the key. For example, with a key of size 3, the
	// 1st, 4th, 7th bytes, etc., are all XORed against the first byte of the
	// key, the 2nd, 5th, 8th bytes against the second byte of the key, and so
	// on.
	// To break the cipher, we have to analyze all bytes encrypted with the
	// same key's byte together. This requires transposing the ciphertext so
	// that all bytes encrypted by the first byte of the key are in the first
	// "column", all bytes encrypted by the second byte of the key are in the
	// second "column" and so on.
	for index, char := range cipherText {
		var (
			// The position of this byte within its block of the transposed
			// cipher text. It determines which byte of the key was used to
			// encrypt this particular byte of the cipher text.
			// For example, for a key size of 3, byte positions 0, 3, 6,...
			// will have byteIdx as 0; positions 1, 4, 7,... will have byteIdx
			// 1, and so on.
			byteIdx = index % keySize

			// The index of the block of the transposed cipher text in which
			// this byte is located.
			blockIdx = index / keySize

			// We are treating the transposed cipher text as a 2D matrix where
			// byteIdx is the row and blockIdx is the column.
			// That is, this is the index of this byte in the transposed matrix
			// where each row represents a position in the key, and each column
			// represents a sequential block of key-sized length.
			transposedIndex = byteIdx*nBlocks + blockIdx
		)

		// Handle the case where we would be out-of-bounds due to an incomplete
		// last block. We need to adjust the transposedIndex to ensure we don't
		// go out of range.
		if transposedIndex >= cipherTextLen {
			var (
				// the current row in the transposed blocks.
				currRow = byteIdx + 1

				// how many bytes are missing in the last, incomplete block.
				missingBytesInLastBlock = keySize - cipherTextLen%keySize
			)

			// By multiplying these two, we calculate the total number of
			// "missing" positions up to the current row.
			// Subtracting this from transposedIndex adjusts our index to
			// account for the absence of these positions in the transposed
			// blocks.
			transposedIndex -= currRow * missingBytesInLastBlock
		}

		transposed[transposedIndex] = char
	}

	// Put together the decryption key.
	// For each block in the transposed cipher-text, the single-byte XOR key
	// that produces the best looking histogram is the repeating-key XOR key
	// byte for that block.
	decryptionKey := make([]byte, keySize)
	for k := range keySize {

		// Define the start and end indices of the transposed block that
		// corresponds to the k-th byte of the key.
		// That is, this block contains all the bytes that were XORed with the
		// same byte of the key during encryption.
		blockStart := k * nBlocks

		// remember that this is the transposed matrix, therefore each row has
		// nBlocks columns.
		blockEnd := blockStart + nBlocks

		// Ensure we don't go beyond the end of the transposed slice, which can
		// happen if the last block is not full.
		if blockEnd > len(transposed) {
			blockEnd = len(transposed)
		}

		block := transposed[blockStart:blockEnd]
		_, blockKey := singleByteXOR(block)

		decryptionKey[k] = blockKey
	}

	plainText := repeatingKeyXOR(cipherText, decryptionKey)

	return string(plainText), string(decryptionKey), nil
}

// decryptAESECBString is a wrapper of decryptAESECB for when you have a cipher
// text to decrypt and a key to decrypt it as strings.
func decryptAESECBString(cipherText, key string) (string, error) {
	plainText, err := decryptAESECB([]byte(cipherText), []byte(key))
	return string(plainText), err
}

// decryptAESECB decrypts a cipher text encrypted using AES-128 in ECB mode with
// the given key.
// Challenge 7 of Set 1.
func decryptAESECB(cipherText, key []byte) ([]byte, error) {
	var (
		cipherTextLen = len(cipherText)
		keyLen        = len(key)
	)
	if cipherTextLen%keyLen != 0 {
		const formatStr = "cipher text length %d is not a multiple of the key size %d"
		return nil, fmt.Errorf(formatStr, cipherTextLen, keyLen)
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("instantiating AES ECB cipher: %w", err)
	}

	var (
		blockSize = aesCipher.BlockSize()
		nBlocks   = (cipherTextLen + blockSize - 1) / blockSize
		plainText = make([]byte, cipherTextLen)
	)
	for b := range nBlocks {
		var (
			start = b * blockSize
			end   = start + blockSize
		)
		aesCipher.Decrypt(plainText[start:end], cipherText[start:end])
	}

	return plainText, nil
}

// isEncryptedAESECBString is a wrapper around isEncryptedAESECB for when you
// have a cipher text to decrypt as a string.
func isEncryptedAESECBString(cipherText string) bool {
	return isEncryptedAESECB([]byte(cipherText))
}

// isEncryptedAESECB returns true if the given cipherText was encrypted using
// AES ECB. It leverages the fact that ECB is stateless and deterministic; the
// same 16 byte plaintext block will always produce the same 16 byte
// ciphertext.
// Challenge 8 of Set 1.
func isEncryptedAESECB(cipherText []byte) bool {
	const blockSize = aes.BlockSize

	cipherTextLen := len(cipherText)
	if cipherTextLen%blockSize != 0 {
		return false
	}

	type block [blockSize]byte

	var (
		nBlocks = (cipherTextLen + blockSize - 1) / blockSize
		set     = make(map[block]struct{}, nBlocks)
	)
	for b := range nBlocks {
		var (
			start = b * blockSize
			end   = start + blockSize

			// get the slice's underlying array
			currBlock = (block)(cipherText[start:end])
		)
		if _, ok := set[currBlock]; ok {
			return true
		}
		set[currBlock] = struct{}{}
	}
	return false
}

// xorWithChar XORs each byte of data with the provided character.
func xorWithChar(data []byte, char byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ char
	}
	return result
}

// computeTextScore calculates and returns a score for the given text based on
// how closely its character frequencies match typical English text. A higher
// score indicates a closer match to valid English.
func computeTextScore(data []byte) float64 {
	const uppercaseToLowercaseShift = 'a' - 'A'
	var (
		// we use [utf8.RuneCountInString] instead of len(text) because
		// len(text) returns the number of *bytes*. However, recall that in
		// UTF-8 some characters are encoded using 2 bytes, therefore len(text)
		// could return a number which is higher than the actual number of
		// characters in the text. In contrast [utf8.RuneCountInString] returns
		// the exact number of *characters* in the text, which is what we want
		// here.
		nChars = float64(utf8.RuneCount(data))
		score  float64
	)

	for _, b := range data {
		if b >= 'A' && b <= 'Z' {
			b += uppercaseToLowercaseShift
		}

		if b >= 'a' && b <= 'z' {
			score += _englishLetterFrequencies[b-'a']
		} else if b == ' ' {
			score += _spaceFrequency
		}
	}

	// Normalization: a longer text will have a higher score because it has more
	// characters. By normalizing, we adjust for the length of the text, making
	// scores from different text lengths comparable.
	// By doing this, the function calculates the average score per character,
	// giving a metric that represents the "English-likeness" of the text on a
	// per-character basis.
	return score / nChars
}

// hammingDistance computes the Hamming distance between two byte slices.
// The Hamming distance is the number of differing bits between two binary
// representations.
func hammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("byte slices are of different lengths")
	}

	var distance int
	for i := range a {
		// XOR the bytes: The result has a '1' bit wherever the two original
		// bytes differ.
		xor := a[i] ^ b[i]

		// Count the number of set bits in the XOR result, adding to the total.
		distance += bits.OnesCount8(xor)
	}

	return distance, nil
}

// estimateKeySize tries to deduce the most probable key size for a given
// ciphertext.
// It computes the normalized Hamming distances between blocks of bytes of the
// ciphertext. The key size producing the smaller Hamming distance between
// blocks is the most likely key size used to encrypt the ciphertext.
// This function takes in a ciphertext and a maximum key size to consider.
// It returns the guessed key size and any potential error encountered.
func estimateKeySize(cipherText []byte, maxKeySize int) (int, error) {
	var (
		cipherTextLen = len(cipherText)
		minEditDist   = math.MaxFloat64
		keySizeGuess  int
		errG          errgroup.Group
		mu            sync.Mutex
	)

	// the loop condition size*2 < cipherTextLen is there to ensure we can
	// have at least two blocks of cipher-text to compare using the Hamming
	// distance.
	for size := 2; size <= maxKeySize && size*2 < cipherTextLen; size++ {

		k := size
		errG.Go(func() error {

			// Calculate the number of pairs of blocks we can compare for this
			// key size.
			nPairs := cipherTextLen / (2 * k)

			var totEditDist int
			for pair := range nPairs {
				var (
					// blockA's start index is calculated as pair*2*k.
					// Each pair covers 2*k bytes in the ciphertext.
					// So, for the n-th pair, blockA starts at 2*k and occupies
					// the first k bytes.
					// For example, for the first pair (pair=0), blockA covers
					// bytes from position 0 to k-1.
					blockA = cipherText[pair*2*k : (pair*2+1)*k]

					// blockB's start index is (pair*2+1)*k, which is
					// immediately after blockA's end index.
					// It covers the next k bytes in the ciphertext.
					// So, for the first pair, this would be from position k to
					// 2k-1.
					blockB = cipherText[(pair*2+1)*k : (pair*2+2)*k]
				)
				editDist, err := hammingDistance(blockA, blockB)
				if err != nil {
					return fmt.Errorf("key length %d: %s", k, err)
				}

				totEditDist += editDist
			}

			var (
				avgEditDist        = float64(totEditDist) / float64(nPairs)
				normalizedEditDist = avgEditDist / float64(k)
			)

			mu.Lock()
			if normalizedEditDist < minEditDist {
				minEditDist = normalizedEditDist
				keySizeGuess = k
			}
			mu.Unlock()

			// log.Println("key size:", k, "edit distance:", normalizedEditDist)

			return nil
		})
	}

	if err := errG.Wait(); err != nil {
		return 0, fmt.Errorf("estimating key length: %s", err)
	}

	return keySizeGuess, nil
}
