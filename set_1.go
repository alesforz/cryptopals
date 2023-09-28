package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
	"sync"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"
)

// Challenge 1 of Set 1.
// HexToBase64 converts a hexadecimal string to its Base64 representation.
func HexToBase64(inputHex string) (string, error) {
	decoded, err := hex.DecodeString(inputHex)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", inputHex)
	}

	return base64.StdEncoding.EncodeToString(decoded), nil
}

// Challenge 2 of Set 1.
// XORHexStrings performs a bitwise XOR operation between two input hexadecimal strings
// of equal length and returns the result as a hexadecimal string.
func XORHexStrings(inputHex1, inputHex2 string) (string, error) {
	// We decode the hex strings to bytes before checking their length, because the byte
	// length might be different from the hex string length due to how hexadecimal
	// encoding works, and direct string length comparison might not always give you the
	// correct assessment.
	decoded1, err := hex.DecodeString(inputHex1)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", inputHex1)
	}

	decoded2, err := hex.DecodeString(inputHex2)
	if err != nil {
		return "", fmt.Errorf("malformed input hex string: %x", inputHex2)
	}

	if len(decoded1) != len(decoded2) {
		return "", fmt.Errorf("decoded bytes are of different lengths, but must be equal")
	}

	// we could reuse decoded1 to save an allocation, but I think creating a separate slice makes
	// the code clearer.
	result := make([]byte, len(decoded1))
	for i := range decoded1 {
		result[i] = decoded1[i] ^ decoded2[i]
	}

	return hex.EncodeToString(result), nil
}

// Challenge 3 of Set 1.
// SingleByteXOR attempts to decrypt a given ciphertext by XORing it against
// each 255 1-byte keys. It then checks which resulting plaintext has character
// frequencies closest to typical English text.
func SingleByteXOR(cipherText []byte) (string, byte) {
	var (
		bestScore float64
		plainText string
		key       byte
	)
	for char := 0; char <= 255; char++ {
		decrypted := xorWithChar(cipherText, byte(char))
		score := computeScore(decrypted)

		if score > bestScore {
			bestScore = score
			plainText = string(decrypted)
			key = byte(char)
		}
	}

	return plainText, key
}

// Challenge 5 of Set 1.
// RepeatingKeyXOR encrypts the given text using a repeating-key XOR operation.
// The function takes in a plain text and a key as input. Each byte of the text is XORed
// with a corresponding byte from the key. If the length of the text exceeds the length of
// the key, the key is repeated cyclically.
// For example, if the text is "HELLO" and the key is "AB", the effective key used for
// encryption would be "ABABA".
func RepeatingKeyXOR(plainText, key []byte) []byte {
	var (
		cipherText = make([]byte, len(plainText))
		keyLen     = len(key)
	)
	for i := range plainText {
		cipherText[i] = plainText[i] ^ key[i%keyLen]
	}

	return cipherText
}

// Challenge 6 of Set 1.
func BreakRepeatingKeyXOR(cipherText []byte, maxKeySize uint) (string, string, error) {

	keySize, err := estimateKeySize(cipherText, maxKeySize)
	if err != nil {
		return "", "", fmt.Errorf("breaking repeating key XOR: %s", err)
	}

	var (
		cipherTextLen = uint(len(cipherText))
		transposed    = make([]byte, cipherTextLen)

		// if the cipher-text length isn't a multiple of the key's size, there will be one
		// last block of length < keySize which we need to consider.
		// By adding keySize - 1 before the division, we're "rounding up" the number of
		// blocks, thus giving us the correct number of blocks even if there's a remainder.
		nBlocks = (cipherTextLen + keySize - 1) / keySize
	)

	// Loop through all indices of the input cipherText.
	// Now that we have an estimation of the key's size, we break the ciphertext into
	// blocks of keySize length and transpose them.
	for index := uint(0); index < cipherTextLen; index++ {
		var (
			byteIdx  = index % keySize // the position within a block.
			blockIdx = index / keySize // the block number.

			// Compute the transposedIndex by treating the cipherText as a 2D matrix
			// where byteIdx is the row and blockIdx is the column. We then transpose
			// this matrix by switching the rows and columns.
			transposedIndex = byteIdx*nBlocks + blockIdx
		)

		// Handle the case where we would be out-of-bounds due to an incomplete last block.
		// We need to adjust the transposedIndex to ensure we don't go out of range.
		if transposedIndex >= cipherTextLen {

			// byteIdx + 1: the current row in the transposed blocks.
			// keySize - cipherTextLen%keySize: Calculates how many bytes are missing in
			// the last, incomplete block.
			// By multiplying these two, we calculate the total number of "missing"
			// positions up to the current row.
			// Subtracting this from transposedIndex adjusts our index to account for the
			// absence of these positions in the transposed blocks.
			transposedIndex -= (byteIdx + 1) * (keySize - cipherTextLen%keySize)
		}

		transposed[transposedIndex] = cipherText[index]
	}

	// Put together the decryption key.
	// For each block in the transposed cipher-text, the single-byte XOR key that produces
	// the best looking histogram is the repeating-key XOR key byte for that block.
	decryptionKey := make([]byte, keySize)
	for k := uint(0); k < keySize; k++ {

		// Define the start and end indices of the transposed block.
		blockStart := k * nBlocks
		blockEnd := blockStart + nBlocks

		// Ensure we don't go beyond the end of the transposed slice.
		if blockEnd > uint(len(transposed)) {
			blockEnd = uint(len(transposed))
		}

		block := transposed[blockStart:blockEnd]
		_, blockKey := SingleByteXOR(block)

		decryptionKey[k] = blockKey
	}

	plainText := RepeatingKeyXOR(cipherText, decryptionKey)

	return string(plainText), string(decryptionKey), nil
}

// xorWithChar decrypts a byte slice by XORing each byte with the provided character.
func xorWithChar(data []byte, char byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ char
	}
	return result
}

// computeScore calculates and returns a score for the given data based on how closely its
// character frequencies match typical English text. A higher score indicates a closer
// match to English.
func computeScore(data []byte) float64 {
	const uppercaseToLowercaseShift = 'a' - 'A'
	var (
		// we use [utf8.RuneCountInString] instead of len(text) because len(text) returns
		// the number of *bytes*. However, recall that in UTF-8 some characters are
		// encoded using 2 bytes, therefore len(text) could return a number which is
		// higher than the actual number of characters in the text. In contrast
		// [utf8.RuneCountInString] returns the exact number of *characters* in the text,
		// which is what we want here.
		totalChars = float64(utf8.RuneCount(data))
		score      float64
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
	// characters. By normalizing, we adjust for the length of the text, making scores
	// from different text lengths comparable.
	// By doing this, the function calculates the average score per character, giving
	// metric that represents the "English-likeness" of the text on a per-character basis.
	return score / totalChars
}

// hammingDistance computes the Hamming distance between two byte slices.
// The Hamming distance is the number of differing bits between two binary representations.
func hammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("byte slices are of different lengths")
	}

	distance := 0
	for i := range a {
		// XOR the bytes: The result has a '1' bit wherever the two original bytes differ.
		xorResult := a[i] ^ b[i]

		// Count the number of set bits in the XOR result, adding to the total.
		distance += bits.OnesCount8(xorResult)
	}

	return distance, nil
}

// estimateKeySize tries to deduce the most probable key size for a given ciphertext.
// It uses the method of computing normalized Hamming distances between blocks of bytes in
// the ciphertext. This function takes in a ciphertext and a maximum key size to consider.
// It returns the guessed key size and any potential error encountered.
func estimateKeySize(cipherText []byte, maxKeySize uint) (uint, error) {
	var (
		cipherTextLen = uint(len(cipherText))
		minEditDist   = math.MaxFloat64
		keySizeGuess  uint
		eg            errgroup.Group
		mu            sync.Mutex
	)

	// the loop condition keySize*2 < cipherTextLen is there to ensure we can have at
	// least two blocks of cipher-text to compare using the Hamming distance.
	for keySize := uint(2); keySize <= maxKeySize && keySize*2 < cipherTextLen; keySize++ {

		k := keySize
		eg.Go(func() error {

			// Calculate the number of pairs of blocks we can compare for this key size.
			nPairs := cipherTextLen / (2 * k)

			var totEditDist float64
			for pair := uint(0); pair < nPairs; pair++ {
				var (
					// blockA's start index is calculated as pair*2*k.
					// Each pair covers 2*k bytes in the ciphertext.
					// So, for the n-th pair, blockA begins at the start of this 2*k-byte
					// range and occupies the first k bytes.
					// For example, for the first pair (pair=0), blockA covers bytes from
					// position 0 to k-1.
					blockA = cipherText[pair*2*k : (pair*2+1)*k]

					// blockB's start index is (pair*2+1)*k, which is immediately after
					// blockA's end index.
					// It covers the next k bytes in the ciphertext.
					// So, for the first pair, this would be from position k to 2k-1.
					blockB = cipherText[(pair*2+1)*k : (pair*2+2)*k]
				)
				editDist, err := hammingDistance(blockA, blockB)
				if err != nil {
					return fmt.Errorf("key length %d: %s", k, err)
				}

				totEditDist += float64(editDist)
			}

			var (
				avgEditDist        = totEditDist / float64(nPairs)
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

	if err := eg.Wait(); err != nil {
		return 0, fmt.Errorf("estimating key length: %s", err)
	}

	return keySizeGuess, nil
}
