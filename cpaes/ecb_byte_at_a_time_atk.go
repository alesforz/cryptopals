// Code in this file solves challenge 12 of set 2 of the Cryptopals.
package cpaes

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"

	"github.com/alesforz/cryptopals/cpbytes"
)

// byteAtTimeAtk implements a byte-at-a-time decryption attack, aka padding oracle
// attack.
// It decrypts a secret by iteratively guessing each byte of the plain text.
// It first crafts plain texts, then asks the oracle to encrypt them, and finally
// compares the resulting cipher text blocks to the target cipher text.
// This sort of input manipulation allows it to deduce each byte of the secret one
// at a time, thus reconstructing it without needing the encryption key.
// This method exploits the deterministic nature of block ciphers and the feedback
// from the oracle to reveal the hidden data.
// See file example_byte_at_a_time_atk.txt for a visual example of this method.
// Challenge 12 of set 2.
func byteAtTimeAtk(ECBOracle Oracle) ([]byte, error) {
	blkSize, secretLen := findECBBlockSizeAndSuffixLength(ECBOracle)
	fmt.Println("block size:", blkSize)
	fmt.Println("suffix length:", secretLen)

	if blkSize != aes.BlockSize {
		const formatStr = "block size %d is not equal to AES block size %d"
		return nil, fmt.Errorf(formatStr, blkSize, aes.BlockSize)
	}

	testBuf := bytes.Repeat([]byte{0x00}, blkSize*2)
	if !detectECB(ECBOracle(testBuf)) {
		return nil, fmt.Errorf("oracle doesn't encrypt with AES ECB")
	}

	var (
		// Craft blocks of known bytes shorter than a full AES block.
		// These will push the unknown byte(s) of the secret into a predictable
		// position within the ciphertext block.
		// For example, if the block is of length 15 (blockSize - 1), the
		// encrypted output will have the first 15 bytes as 'A' and the 16th byte
		// will be the first byte of the secret. With length 14, the encrypted
		// output will have the first 15 bytes as 'A' and the 15th and 16th will be
		// the first 2 bytes of the secret.
		blkDict = makeBlockDict(blkSize)

		// Store the cipher text for each block in the dictionary to avoid calling
		// the oracle multiple times for the same block during the attack.
		cipherTextCache = makeBlockCipherTextCache(blkDict, ECBOracle)

		nSecretBlks = (secretLen + blkSize - 1) / blkSize
		secret      = make([]byte, 0, secretLen)
	)
	for blkIdx := range nSecretBlks {
		for size := blkSize - 1; size >= 0; size-- {
			var (
				knownBytes = blkDict[size]

				// A combination of known bytes, previously decrypted bytes of the
				// secret, and the byte currently being guessed (the +1, which we
				// will brute force.
				forgedBlk = make([]byte, len(knownBytes)+len(secret)+1)
			)
			copy(forgedBlk, knownBytes)
			copy(forgedBlk[len(knownBytes):], secret)

			var (
				blkStart = blkIdx * blkSize
				blkEnd   = blkStart + blkSize

				// the cipher text block being targeted for decryption.
				targetBlk = cipherTextCache[size][blkStart:blkEnd]
			)
			guessedByte := guessByte(forgedBlk, targetBlk, blkIdx, ECBOracle)
			secret = append(secret, guessedByte)

			// uncomment to see decryption byte by byte
			// fmt.Printf("%s\n", secret)
			// time.Sleep(100 * time.Millisecond)

			if len(secret) == secretLen {
				// we have decrypted the entire secret
				return secret, nil
			}
		}
	}

	panic("something went wrong: couldn't decrypt the secret")
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
// Part of challenge 12 of set 2.
func findECBBlockSizeAndSuffixLength(oracle Oracle) (int, int) {
	var (
		blkSize int

		// suffixLength is the number of bytes of unknown data the oracle appends
		// after the plain text, before applying padding and encryption.
		suffixLength int
		cipherLen    = len(oracle([]byte{}))
	)
	for i := 1; ; i++ {
		nextCipherLen := len(oracle(bytes.Repeat([]byte{'a'}, i)))
		if nextCipherLen > cipherLen {
			// We feed an increasing amount of 'a' to the encryption oracle until
			// the length of the resulting cipher text increases.

			// The increase (nextCipherLen – cipherLen) equals the block size,
			// because the cipher text must have increased by exactly 1 block.
			blkSize = nextCipherLen - cipherLen

			// It took i amount of 'a's to increase the cipher text length.
			// Therefore unknown suffix must be (cipherLen – i) bytes long.
			suffixLength = cipherLen - i
			break
		}
	}

	return blkSize, suffixLength
}

// makeBlockDict generates a lookup table of plaintext blocks of lengths 0 up to
// blockSize−1, each filled entirely with the ASCII character 'A'.
// This is a useful tool for the byte-at-a-time decryption attack.
// Part of challenge 12 of set 2.
func makeBlockDict(blkSize int) [][]byte {
	blkDict := make([][]byte, blkSize)

	for size := range blkSize {
		blk := make([]byte, size)
		for i := range size {
			blk[i] = 'A'
		}

		blkDict[size] = blk
	}

	return blkDict
}

// makeBlockCipherTextCache generates a cache of cipher texts for each block
// in the given block dictionary.
// It uses the provided oracle to encrypt each block and stores the resulting
// cipher text in the cache.
// It does not modify the input slice.
// Part of challenge 12 of set 2.
func makeBlockCipherTextCache(blkDict [][]byte, oracle Oracle) [][]byte {
	cache := make([][]byte, len(blkDict))

	for i, blk := range blkDict {
		cache[i] = oracle(blk)
	}

	return cache
}

// guessByte brute-forces a single unknown byte of the secret by comparing the
// oracle's outputs for all 256 possible byte values against a target ciphertext
// block.
// forgedBlk is the plaintext block with one slot (last byte) reserved for guessing.
// It's safe to modify this slice, as it is a copy of the original plaintext block
// and the calling function will not use it again.
// targetBlk is the ciphertext block we aim to reproduce by encrypting
// [forgedBlk|guessByte].
// blkIdx is the index in the ciphertext of the block we are currently decrypting.
//
// guessByte returns correctly guessed secret byte (0–255), or panics if no match
// is found.
// Part of challenge 12 of set 2.
func guessByte(forgedBlk, targetBlk []byte, blkIdx int, ECBOracle Oracle) byte {
	var (
		blkSize  = len(targetBlk)
		blkStart = blkIdx * blkSize
		blkEnd   = blkStart + blkSize
	)
	// the "byte-at-a-time" part of the attack.
	// This loop is responsible for guessing the value of the unknown byte of the
	// secret by iterating through all possible byte values (0 to 255) and checking
	// which one produces a ciphertext block that matches the target block.
	// Basically, what we are doing is asking the oracle to encrypt all the possible
	// byte sequences obtained by changing their last byte.
	// For example:
	// oracle("AAAAAAAAAAAAAAAA")
	// oracle("AAAAAAAAAAAAAAAB")
	// oracle("AAAAAAAAAAAAAAAC")
	// oracle("AAAAAAAAAAAAAAAD")
	// .....
	// until the resulting cipher text matches the target block.
	// If the cipher text generated by oracle("AAAAAAAAAAAAAAAD") matches, then 'D'
	// is a byte of the secret.
	// On the next round we will try all possible byte sequences like this:
	// oracle("AAAAAAAAAAAAAADA")
	// oracle("AAAAAAAAAAAAAADB")
	// oracle("AAAAAAAAAAAAAADC")
	// oracle("AAAAAAAAAAAAAADD")
	// .....
	// until the resulting cipher text matches the target block.
	// If the cipher text generated by oracle("AAAAAAAAAAAAAADA") matches, then 'A'
	// is the next byte of the secret.
	// And so on until we decrypted the entire secret.
	for i := range 255 {
		guessByte := byte(i)

		// append the byte we are using as a guess to the end of the forged block.
		// Recall that forgedBlk has an extra byte at the end to accommodate the
		// guess byte.
		forgedBlk[len(forgedBlk)-1] = guessByte

		cipherText := ECBOracle(forgedBlk)

		cipherTextBlk := cipherText[blkStart:blkEnd]
		if bytes.Equal(cipherTextBlk, targetBlk) {
			return guessByte
		}
	}

	// we should never reach this point
	panic("something went wrong: couldn't guess correct byte of cipher text")
}
