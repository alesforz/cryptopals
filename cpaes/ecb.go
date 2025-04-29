package cpaes

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"

	"github.com/alesforz/cryptopals/cpbytes"
	"github.com/alesforz/cryptopals/cppad"
)

// encryptECB encrypts a plain text using AES-128 in ECB mode with the given key.
// It pads the plain text using PKCS#7 padding to ensure its length is a multiple
// of the block size.
// The function does not modify the input slices.
func encryptECB(plainText, key []byte) ([]byte, error) {
	plainText = cppad.PKCS7(plainText, aes.BlockSize)

	encrypter, err := encryptionOracle(key)
	if err != nil {
		return nil, fmt.Errorf("initializing encryption oracle: %s", err)
	}

	var (
		pLen       = len(plainText)
		blkSize    = aes.BlockSize
		nBlocks    = (pLen + blkSize - 1) / blkSize
		cipherText = make([]byte, 0, pLen)
	)
	for i := range nBlocks {
		var (
			start        = i * blkSize
			end          = start + blkSize
			encryptedBlk = encrypter(plainText[start:end])
		)
		cipherText = append(cipherText, encryptedBlk...)
	}

	return cipherText, nil
}

// decryptECB decrypts a cipher text encrypted using AES-128 in ECB mode with the
// given key.
// The function does not modify the input slices.
// (Solves challenge 7 of set 1)
func decryptECB(cipherText, key []byte) ([]byte, error) {
	cLen, kLen := len(cipherText), len(key)
	if cLen%kLen != 0 {
		const errStr = "cipher text's length (%d) is not a multiple of the decryption key's length (%d)"
		return nil, fmt.Errorf(errStr, cLen, kLen)
	}

	decrypter, err := decryptionOracle(key)
	if err != nil {
		return nil, fmt.Errorf("initializing decryption oracle: %s", err)
	}

	var (
		blkSize   = kLen
		nBlocks   = (cLen + blkSize - 1) / blkSize
		plainText = make([]byte, 0, cLen)
	)
	for i := range nBlocks {
		var (
			blkStart     = i * blkSize
			blkEnd       = blkStart + blkSize
			decryptedBlk = decrypter(cipherText[blkStart:blkEnd])
		)
		plainText = append(plainText, decryptedBlk...)
	}

	return plainText, nil
}

// detectECB returns true if the given cipherText was encrypted using AES ECB.
// It leverages the fact that ECB is stateless and deterministic; the same 16 byte
// plaintext block will always produce the same 16 byte ciphertext.
// detectECB does not modify the input slice.
// (Solves challenge 8 of set 1)
func detectECB(cipherText []byte) bool {
	const blkSize = aes.BlockSize

	cLen := len(cipherText)
	if cLen%blkSize != 0 {
		return false
	}

	var (
		nBlocks = (cLen + blkSize - 1) / blkSize
		blkSet  = make(map[Block]struct{}, nBlocks)
	)
	for i := range nBlocks {
		var (
			blkStart = i * blkSize
			blkEnd   = blkStart + blkSize

			// get the slice's underlying array
			currBlk = (Block)(cipherText[blkStart:blkEnd])
		)
		if _, ok := blkSet[currBlk]; ok {
			// if we have already seen this block, then the cipherText was encrypted
			// using ECB.
			return true
		}
		blkSet[currBlk] = struct{}{}
	}
	return false
}

// randomEncryption chooses to encrypt using AES ECB 1/2 the time, and using AES CBC
// the other half (using a random IV).
// The function does not modify the input slice.
// (Solves challenge 11 of set 2)
func randomEncryption(plainText []byte) ([]byte, error) {
	padded, err := cpbytes.AddNoise(plainText, 5, 10)
	if err != nil {
		return nil, fmt.Errorf("adding noise to plain text: %s", err)
	}

	key, err := cpbytes.Random(aes.BlockSize, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random AES key: %s", err)
	}

	if coinFlip := rand.IntN(2); coinFlip == 0 {
		return encryptECB(padded, key)
	}

	iv, err := cpbytes.Random(aes.BlockSize, aes.BlockSize)
	if err != nil {
		const formatStr = "generating random IV for AES CBC encryption: %s"
		return nil, fmt.Errorf(formatStr, err)
	}

	return encryptCBC(padded, key, iv)
}

func decryptECBOracleSecret(ECBOracle Oracle) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// ecbEncryptionOracleWithSecret returns an AES oracle that appends a secret string
// to the given plain text before encrypting it using AES ECB.
// ecbEncryptionOracleWithSecret generates a random encryption key that the oracle
// will use to encrypt.
// Part of challenge 12 of set 2.
func ecbEncryptionOracleWithSecret() (Oracle, error) {
	// the secret is given by the challenge description
	const secretBase64 = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`

	secret, err := base64.StdEncoding.DecodeString(secretBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding secret from base64: %s", err)
	}

	key, err := cpbytes.Random(aes.BlockSize, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("generating random AES key: %s", err)
	}

	oracle := func(plainText []byte) []byte {
		plainTextWithSecret := make([]byte, len(plainText)+len(secret))
		copy(plainTextWithSecret, plainText)
		copy(plainTextWithSecret[len(plainText):], secret)

		cipherText, err := encryptECB(plainTextWithSecret, key)
		if err != nil {
			panic(err)
		}

		return cipherText
	}

	return oracle, nil
}

// findECBBlockSizeAndSuffixLength probes the given ECB encryption oracle to discover
// two key parameters: the cipher’s block size in bytes, and the number of unknown
// bytes the oracle appends before encryption.
// It returns the block size and the suffix length.
func findECBBlockSizeAndSuffixLength(oracle Oracle) (int, int) {
	var (
		blockSize int

		// suffixLength is the number of bytes of unknown data the oracle appends
		// after the plain text, before applying padding and encryption.
		suffixLength int
		cipherLen    = len(oracle([]byte{'a'}))
	)
	for i := 2; ; i++ {
		nextCipherLen := len(oracle(bytes.Repeat([]byte{'a'}, i)))
		if nextCipherLen > cipherLen {
			// We feed an increasing amount of 'a' to the encryption oracle until
			// the length of the resulting cipher text increases.

			// The increase (nextCipherLen – cipherLen) equals the block size,
			// because the cipher text must have increased by exactly 1 block.
			blockSize = nextCipherLen - cipherLen

			// It took i amount of 'a's to increase the cipher text length.
			// Therefore unknown suffix must be (cipherLen – i) bytes long.
			suffixLength = cipherLen - i
			break
		}
	}

	return blockSize, suffixLength
}
