package cpaes

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"

	"github.com/alesforz/cryptopals/cpbytes"
	"github.com/alesforz/cryptopals/cpxor"
)

// EncryptCTR encrypts the input byte slice using AES in CTR mode with the given key
// and nonce.
func EncryptCTR(input, key []byte, nonce uint64) ([]byte, error) {
	return ctr(input, key, nonce)
}

// DecryptCTR decrypts the input byte slice using AES in CTR mode with the given key
// and nonce.
func DecryptCTR(input, key []byte, nonce uint64) ([]byte, error) {
	return ctr(input, key, nonce)
}

// ctr performs AES encryption/decryption in CTR mode.
// Since CTR mode is a stream cipher mode, encryption and decryption are the same
// operation.
// input is the byte slice to be encrypted/decrypted.
// key is the AES key.
// ctr does not modify the input slices.
func ctr(input, key []byte, nonce uint64) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("input length must be greater than 0")
	}
	if len(key)%aes.BlockSize != 0 {
		return nil, fmt.Errorf(
			"AES key length must be a multiple of %d bytes, got %d bytes",
			aes.BlockSize,
			len(key),
		)
	}

	inputBlks, err := toChunks(input, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	var (
		counter      uint64
		keystreamBlk = make([]byte, aes.BlockSize)
		output       = make([]byte, 0, len(input))
	)
	encryptOracle, err := encryptionOracle(key)
	if err != nil {
		return nil, fmt.Errorf("creating encryption oracle: %s", err)
	}

	binary.LittleEndian.PutUint64(keystreamBlk[:8], nonce)
	for i := range inputBlks {
		// encrypt [nonce || counter] to get the keystream block
		binary.LittleEndian.PutUint64(keystreamBlk[8:], counter)
		keystreamBlkEncrypted := encryptOracle(keystreamBlk)

		// if it's a partial block, slice the keystream accordingly
		// covers the case where the input length is not a multiple of the block size
		// so the last block is shorter than a full block.
		if len(inputBlks[i]) < aes.BlockSize {
			keystreamBlkEncrypted = keystreamBlkEncrypted[:len(inputBlks[i])]
		}

		outputBlk, err := cpxor.Blocks(inputBlks[i], keystreamBlkEncrypted)
		if err != nil {
			return nil, fmt.Errorf(
				"XORing cipher text block %d with keystream: %s",
				i,
				err,
			)
		}
		output = append(output, outputBlk...)
		counter++
	}

	return output, nil
}

// toChunks splits the input byte slice into chunks of the specified size.
// If the input length is not a multiple of the chunk size, the last chunk will
// be a partial chunk.
// It does not modify the input slice.
func toChunks(input []byte, chunkSize uint) ([][]byte, error) {
	if uint(len(input))%chunkSize == 0 {
		inputBlks, err := cpbytes.ToChunks(input, int(chunkSize))
		if err != nil {
			return nil, fmt.Errorf("splitting cipher text into blocks: %s", err)
		}
		return inputBlks, nil
	}

	// CTR mode does not require padding, so we handle partial blocks separately
	fullBlks := uint(len(input)) / chunkSize
	inputBlks, err := cpbytes.ToChunks(
		input[:fullBlks*chunkSize],
		int(chunkSize),
	)
	if err != nil {
		return nil, fmt.Errorf("splitting cipher text into blocks: %s", err)
	}
	// slice for that partial block
	lastBlk := input[fullBlks*chunkSize:]
	inputBlks = append(inputBlks, lastBlk)

	return inputBlks, nil
}

func breakCTRWithFixedNonce(cipherTexts [][]byte) ([]byte, error) {
	shortest := len(cipherTexts[0])
	for i := 1; i < len(cipherTexts); i++ {
		if len(cipherTexts[i]) < shortest {
			shortest = len(cipherTexts[i])
		}
	}

	recoveredKeyStream := make([]byte, shortest)
	for colIdx := range shortest {
		// try all printable ASCII characters as the key stream byte for this column
		for char := 32; char <= 126; char++ {
			guesses := make([]byte, 0, len(cipherTexts))
			for _, ct := range cipherTexts {
				guesses = append(guesses, ct[colIdx]^byte(char))
			}
			if isGoodGuess(guesses) {
				recoveredKeyStream[colIdx] = byte(char)
				break
			}
		}
	}
	return recoveredKeyStream, nil
}

func isGoodGuess(guesses []byte) bool {
	for _, g := range guesses {
		if g < 32 || g > 126 {
			return false
		}
	}
	return true
}
