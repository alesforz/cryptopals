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
// Challenge 12 of set 2.
func byteAtTimeAtk(ECBOracle Oracle) ([]byte, error) {
	blkSize, secretLen := findECBBlockSizeAndSuffixLength(ECBOracle)
	// fmt.Println("block size:", blkSize)
	// fmt.Println("suffix length:", secretLen)

	if blkSize != aes.BlockSize {
		const formatStr = "block size %d is not equal to AES block size %d"
		return nil, fmt.Errorf(formatStr, blkSize, aes.BlockSize)
	}

	testBuf := make([]byte, blkSize*2)
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
		// blkDict = [
		//    []
		//    [0]
		//    [00]
		//    [000]
		//    [0000]
		//    [00000]
		//    [000000]
		//    [0000000]
		//    [00000000]
		//    [000000000]
		//    [0000000000]
		//    [00000000000]
		//    [000000000000]
		//    [0000000000000]
		//    [00000000000000]
		//    [000000000000000]
		// ]
		blkDict = makeBlockDict(blkSize)

		// Store the cipher text for each block in the dictionary to avoid calling
		// the oracle multiple times for the same block during the attack.
		// Assume YELLOWSUN is the secret.
		// cipherTextCache = [
		//    pad=0,   [YELLOWSUN*******]
		//    pad=1,   [0YELLOWSUN******]
		//    pad=2,   [00YELLOWSUN*****]
		//    pad=3,   [000YELLOWSUN****]
		//    pad=4,   [0000YELLOWSUN***]
		//    pad=5,   [00000YELLOWSUN**]
		//    pad=6,   [000000YELLOWSUN*]
		//    pad=7,   [0000000YELLOWSUN]
		//    pad=8,   [00000000YELLOWSU | N***************]
		//    pad=9,   [000000000YELLOWS | UN**************]
		//    pad=10,  [0000000000YELLOW | SUN*************]
		//    pad=11,  [00000000000YELLO | WSUN************]
		//    pad=12,  [000000000000YELL | OWSUN***********]
		//    pad=13,  [0000000000000YEL | LOWSUN**********]
		//    pad=14,  [00000000000000YE | LLOWSUN*********]
		//    pad=15,  [000000000000000Y | ELLOWSUN********]
		// ]
		// Recall that the oracle will append the secret immediately after the data
		// we provide.
		//  * means any other character after the secret that we don't care about
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

			// What the above means, graphically:
			// sz=15, forgedBlk=000000000000000, targetBlk=000000000000000Y, guess=Y
			// sz=14, forgedBlk=00000000000000Y, targetBlk=00000000000000YE, guess=E
			// sz=13, forgedBlk=0000000000000YE, targetBlk=0000000000000YEL, guess=L
			// sz=12, forgedBlk=000000000000YEL, targetBlk=000000000000YELL, guess=L
			// sz=11, forgedBlk=00000000000YELL, targetBlk=00000000000YELLO, guess=O
			// sz=10, forgedBlk=0000000000YELLO, targetBlk=0000000000YELLOW, guess=W
			// sz=9,  forgedBlk=000000000YELLOW, targetBlk=000000000YELLOWS, guess=S
			// sz=8,  forgedBlk=00000000YELLOWS, targetBlk=00000000YELLOWSU, guess=U
			// sz=7,  forgedBlk=0000000YELLOWSU, targetBlk=0000000YELLOWSUN, guess=N
			// reconstructed secret = YELLOWSUN
			guessedByte := guessByte(forgedBlk, targetBlk, blkIdx, ECBOracle)
			secret = append(secret, guessedByte)

			// uncomment to see decryption byte by byte
			// fmt.Printf("%q\n", secret)
			// time.Sleep(100 * time.Millisecond)

			// We must stop right after recovering the real SECRET, because beyond
			// that we’re trying to match the oracle’s PKCS#7 padding bytes, and
			// those change size‐by‐size, so no forged block will ever line up.
			//
			// Here is what the additional iterations of the loop would look like:
			// sz=6,  forgedBlk=000000YELLOWSUN, targetBlk=000000YELLOWSUN1, guess=1
			// sz=5,  forgedBlk=00000YELLOWSUN1, targetBlk=00000YELLOWSUN22, guess=??
			// (here the program would panic at the end of guessByte())
			// sz=4,  forgedBlk=0000YELLOWSUN**, targetBlk=0000YELLOWSUN333, guess=??
			// sz=3,  forgedBlk=000YELLOWSUN***, targetBlk=000YELLOWSUN4444, guess=??
			// sz=2,  forgedBlk=00YELLOWSUN****, targetBlk=00YELLOWSUN55555, guess=??
			// sz=1,  forgedBlk=0YELLOWSUN*****, targetBlk=0YELLOWSUN666666, guess=??
			// sz=0,  forgedBlk=YELLOWSUN******, targetBlk=YELLOWSUN7777777, guess=??
			// We changed the '*' for the bytes that the oracle would put there as
			// padding. As you can see, each subsequent block of the cipher text
			// would have a different padding byte. But we construct forgedBlk as:
			// [0x00 *size | known_bytes | guess]
			// For iteration sz=6, we build:
			// forgedBlk=[0x00*6 | YELLOWSUN | _]
			// where '_' is the byte we are guessing. Eventually, guessByte() will
			// append 1 to the forgedBlk, and we will get:
			// forgedBlk=[0x00*6 | YELLOWSUN | 1]
			// which will correctly match the cipher text block of sz=6.
			//
			// But at sz=5, we build:
			// forgedBlk=[0x00*5 | YELLOWSUN1 | _]
			// which will never match the cipher text block of sz=5, which is:
			// [0x00*5 | YELLOWSUN | 22]
			// because the padding has changed!
			// No matter how we guess the last byte, it will never match it, because
			// the known parts are different (we have a 1 in the forged block, but a
			// 2 in the cipher text block).
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
		nextCipherLen := len(oracle(make([]byte, i)))
		if nextCipherLen > cipherLen {
			// We feed an increasing amount of 0x00 bytes to the encryption oracle
			// until the length of the resulting cipher text increases.

			// The increase (nextCipherLen – cipherLen) equals the block size,
			// because the cipher text must have increased by exactly 1 block.
			blkSize = nextCipherLen - cipherLen

			// It took i amount of 0x00 to increase the cipher text length.
			// Therefore unknown suffix must be (cipherLen – i) bytes long.
			suffixLength = cipherLen - i

			// the above, graphically:
			// before loop: cipher text=YELLOWSUN*******, cipherLen=16
			// i=1, cipher text=0YELLOWSUN******, nextCipherLen=16
			// i=2, cipher text=00YELLOWSUN*****, nextCipherLen=16
			// i=3, cipher text=000YELLOWSUN****, nextCipherLen=16
			// i=4, cipher text=0000YELLOWSUN***, nextCipherLen=16
			// i=5, cipher text=00000YELLOWSUN**, nextCipherLen=16
			// i=6, cipher text=000000YELLOWSUN*, nextCipherLen=16
			// i=7, cipher text=0000000YELLOWSUN | ****************, nextCipherLen=16
			// To understand the last iteration, recall that the ECB encryption adds
			// a block of padding if the input is a multiple of the block size.
			// -> nextCipherLen > cipherLen is true
			// -> blkSize = nextCipherLen - cipherLen = 32 - 16 = 16
			// -> suffixLength = cipherLen - i = 16 - 7 = 9
			break
		}
	}

	return blkSize, suffixLength
}

// makeBlockDict generates a lookup table of plaintext blocks of lengths 0 up to
// blockSize−1, each filled with the 0x00 byte.
// This is a useful tool for the byte-at-a-time decryption attack.
// Part of challenge 12 of set 2.
func makeBlockDict(blkSize int) [][]byte {
	blkDict := make([][]byte, blkSize)

	for size := range blkSize {
		blkDict[size] = make([]byte, size)
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
// guessByte returns the correctly guessed secret byte (0–255), or panics if no match
// is found.
// Part of challenge 12 of set 2.
func guessByte(forgedBlk, targetBlk []byte, blkIdx int, ECBOracle Oracle) byte {
	var (
		blkSize  = len(targetBlk)
		blkStart = blkIdx * blkSize
		blkEnd   = blkStart + blkSize
	)
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
	panic("couldn't guess correct byte of cipher text")
}
