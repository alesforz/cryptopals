package cpxor

import (
	"fmt"
	"math"
	"math/bits"
	"sync"

	"golang.org/x/sync/errgroup"
)

// EncryptWithRepeatingKey encrypts the given text using repeating-key XOR.
// Each byte of the text is XORed with a corresponding byte from the key. If the
// length of the text exceeds the length of the key, the key is repeated cyclically.
// For example, if the text is "HELLO" and the key is "AB", the effective key
// used for encryption would be "ABABA".
// It returns the encrypted text as a new byte slice.
// EncryptWithRepeatingKey does not modify the input slices.
// (Solves challenge 5 of set 1).
func EncryptWithRepeatingKey(plainText, key []byte) []byte {
	var (
		cipherText = make([]byte, len(plainText))
		keyLen     = len(key)
	)
	for i := range plainText {
		cipherText[i] = plainText[i] ^ key[i%keyLen]
	}

	return cipherText
}

// DecryptWithRepeatingKey decrypts the given text using repeating-key XOR.
// Each byte of the text is XORed with a corresponding byte from the key. If the
// length of the text exceeds the length of the key, the key is repeated cyclically.
// For example, if the ciphertext is "XXXX" and the key is "AB", the effective key
// used for decryption would be "ABABA".
// It returns the decrypted text as a new byte slice.
// DecryptWithRepeatingKey does not modify the input slices.
// This function is an alias for encryptWithRepeatingKey (since XORing a byte twice
// with the same key byte results in the original byte) added for better readability
// in the context of wanting to decrypt ciphertext.
func DecryptWithRepeatingKey(cipherText, key []byte) []byte {
	return EncryptWithRepeatingKey(cipherText, key)
}

// BreakRepeatingKeyXORCipherKnownSize decrypts a ciphertext encrypted with
// repeating-key XOR when the key size is known. It transposes the ciphertext
// into key-sized columns, recovers each key byte with single-byte XOR
// breaking, and returns the plaintext and key.
func BreakRepeatingKeyXORCipherKnownSize(
	cipherText []byte,
	keySize int,
) ([]byte, []byte, error) {
	if keySize <= 0 {
		return nil, nil, fmt.Errorf("key size must be positive, got %d", keySize)
	}
	if keySize > len(cipherText) {
		errStr := "key size %d exceeds cipher text length %d"
		return nil, nil, fmt.Errorf(errStr, keySize, len(cipherText))
	}

	plainText, key, err := breakRepeatingKeyXORWithKnownSize(cipherText, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("breaking repeating key XOR: %s", err)
	}
	return plainText, key, nil
}

// breakRepeatingKeyXORCipher attempts to decrypt a given cipher text encrypted
// using repeating-key XOR:
// 1. Determines the probable key size using statistical analysis.
// 2. Delegates to the known-size breaker.
// Returns the decrypted text, the key used to encrypt/decrypt it , and an error
// (if any).
// breakRepeatingKeyXORCipher does not modify the input slice.
// (Solves challenge 6 of set 1).
func breakRepeatingKeyXORCipher(
	cipherText []byte,
	maxKeySize int,
) ([]byte, []byte, error) {

	keySize, err := estimateXORKeySize(cipherText, maxKeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("breaking repeating key XOR: %s", err)
	}

	return breakRepeatingKeyXORWithKnownSize(cipherText, keySize)
}

func breakRepeatingKeyXORWithKnownSize(
	cipherText []byte,
	keySize int,
) ([]byte, []byte, error) {
	var (
		cipherTextLen        = len(cipherText)
		transposedCipherText = make([]byte, cipherTextLen)

		// if the cipher-text length isn't a multiple of the key's size, there
		// will be one last block of length < keySize which we need to consider.
		// By adding (keySize - 1) before the division, we're "rounding up" the
		// number of blocks, thus giving us the correct number of blocks even
		// if there's a remainder.
		nBlocks = (cipherTextLen + keySize - 1) / keySize
	)
	// Loop through all indices of the input cipherText.
	// Now that we have a key size, we break the ciphertext into blocks of
	// keySize length and transpose them.
	for cipherTextIndex, cipherTextByte := range cipherText {
		var (
			byteIdx                 = cipherTextIndex % keySize
			blockIdx                = cipherTextIndex / keySize
			transposedCipherTextIdx = byteIdx*nBlocks + blockIdx
		)

		if transposedCipherTextIdx >= cipherTextLen {
			var (
				currRow               = byteIdx + 1
				lastBlockMissingBytes = keySize - cipherTextLen%keySize
			)
			transposedCipherTextIdx -= currRow * lastBlockMissingBytes
		}

		transposedCipherText[transposedCipherTextIdx] = cipherTextByte
	}

	decryptionKey := make([]byte, keySize)
	for k := range keySize {
		var (
			blockStart = k * nBlocks
			blockEnd   = blockStart + nBlocks
		)
		if blockEnd > len(transposedCipherText) {
			blockEnd = len(transposedCipherText)
		}

		var (
			block       = transposedCipherText[blockStart:blockEnd]
			_, blockKey = BreakSingleByteXorCipher(block)
		)
		decryptionKey[k] = blockKey
	}

	plainText := DecryptWithRepeatingKey(cipherText, decryptionKey)

	return plainText, decryptionKey, nil
}

// estimateXORKeySize tries to deduce the most probable key size for a given
// cipher text encrypted with repeating-key XOR.
// It does so by computing the normalized Hamming distances between blocks of bytes
// of the ciphertext. The key size producing the smaller Hamming distance between
// blocks is the most likely key size used to encrypt the ciphertext.
// This function takes in a ciphertext and the maximum key size to consider.
// estimateXORKeySize does not modify the input slice.
func estimateXORKeySize(cipherText []byte, maxKeySize int) (int, error) {
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
			var (
				// Calculate the number of pairs of blocks we can compare for this
				// key size.
				nPairs      = cipherTextLen / (2 * k)
				totEditDist int
			)
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
					errStr := "computing Hamming distance of size %d blocks: %s"
					return fmt.Errorf(errStr, k, err)
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

			return nil
		})
	}

	if err := errG.Wait(); err != nil {
		return 0, fmt.Errorf("estimating XOR key size: %s", err)
	}

	return keySizeGuess, nil
}

// hammingDistance computes the Hamming distance between two byte slices.
// The Hamming distance is the number of differing bits between two binary
// representations.
func hammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		errStr := "input slices are of different lengths: %d and %d"
		return 0, fmt.Errorf(errStr, len(a), len(b))
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
