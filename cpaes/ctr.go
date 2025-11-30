package cpaes

import (
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/alesforz/cryptopals/cpbytes"
	"github.com/alesforz/cryptopals/cpxor"
)

// ctr performs AES encryption/decryption in CTR mode.
// Since CTR mode is a stream cipher mode, encryption and decryption are the same
// operation.
// input is the byte slice to be encrypted/decrypted.
// key is the AES key.
// nonce is an 8-byte slice used as the nonce for CTR mode.
// ctr does not modify the input slices.
func ctr(input, key, nonce []byte) ([]byte, error) {
	var (
		inputBlks [][]byte
		err       error
	)
	if len(input)%aes.BlockSize == 0 {
		if inputBlks, err = cpbytes.ToChunks(input, aes.BlockSize); err != nil {
			return nil, fmt.Errorf("splitting cipher text into blocks: %s", err)
		}
	} else {
		// CTR mode does not require padding, so we handle partial blocks separately
		fullBlks := len(input) / aes.BlockSize
		inputBlks, err = cpbytes.ToChunks(
			input[:fullBlks*aes.BlockSize],
			aes.BlockSize,
		)
		if err != nil {
			return nil, fmt.Errorf("splitting cipher text into blocks: %s", err)
		}
		// slice for that partial block
		lastBlk := input[fullBlks*aes.BlockSize:]
		inputBlks = append(inputBlks, lastBlk)
	}

	var (
		counter      uint64
		counterBytes = make([]byte, 8)
		// nonce in little-endian format
		nonceLE = make([]byte, 8)
		output  = make([]byte, 0, len(input))
	)
	encryptOracle, err := encryptionOracle(key)
	if err != nil {
		return nil, fmt.Errorf("creating encryption oracle: %s", err)
	}

	for i := range inputBlks {
		binary.LittleEndian.PutUint64(nonceLE, binary.LittleEndian.Uint64(nonce))
		binary.LittleEndian.PutUint64(counterBytes, counter)

		// encrypt [nonce || counter] to get the keystream block
		keystreamBlk := slices.Concat(nonceLE, counterBytes)
		keystreamBlk = encryptOracle(keystreamBlk)

		// if it's a partial block, slice the keystream accordingly
		// covers the case where the input length is not a multiple of the block size
		// so the last block is shorter than a full block.
		if len(inputBlks[i]) < aes.BlockSize {
			keystreamBlk = keystreamBlk[:len(inputBlks[i])]
		}

		outputBlk, err := cpxor.Blocks(inputBlks[i], keystreamBlk)
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
