package main

import (
	"fmt"
	"math"
	"math/bits"
	"sync"

	"golang.org/x/sync/errgroup"
)

// breakRepeatingKeyXOR:
// 1. Determines the probable key size using statistical analysis.
// 2. Transposes the cipher text by aligning bytes encrypted with the same key
// byte.
// 3. Recovers the decryption key with frequency analysis on each transposed
// block to determine the key's byte used to encrypt that particular block.
// 4. Decrypts the cipher text
// Returns the decrypted text, the key used to encrypt/decrypt it, and an error
// (if any).
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
