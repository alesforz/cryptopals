// Code in this file solves challenge 12 and 14 of set 2 of the Cryptopals.
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

// ==================================================================================

// byteAtTimeAtkWithPrefix implements a byte-at-a-time decryption attack, aka
// padding oracle attack. It is a more difficult version of the attack implemented in
// byteAtTimeAtk above. Namely, the ecbOracle now encrypts:
// AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
// i.e., it pre-pends a random prefix of random bytes at the beginning of the
// plain text before encryption.
// The strategy we implement is to figure out the length of the random prefix, so
// that we can skip it, thus reducing this attack to its simpler version we
// implemented in byteAtTimeAtk.
// Challenge 14 of set 2.
func byteAtTimeAtkWithPrefix(ecbOracle Oracle) ([]byte, error) {
	blkSize, _ := findECBBlockSizeAndSuffixLength(ecbOracle)
	fmt.Println("block size:", blkSize)

	prefixLen := findPrefixLen(blkSize, ecbOracle)
	fmt.Println("prefix length:", prefixLen)

	var (
		// We build a "wrapper oracle" around the input ecbOracle to turn it from
		// ECB(random-prefix || our-bytes || secret)
		// to an oracle behaving like the easier version of the attack, that is:
		// ECB(our-bytes || secret).

		// Here we calculate how many 0x00 bytes we must prepend so that
		// (random-prefix || filler) ends on a block boundary (read below)
		fillBytesAfterPrefix = blkSize - prefixLen%blkSize

		// wrapperOracle basically hides the random prefix from the byteAtTimeAtk
		// function, making it behave like the oracle that we used in the
		// implementation of that attack.
		wrapperOracle = Oracle(func(plainText []byte) []byte {
			// For example, P=prefix, T=our text, S=Secret, *=padding
			// PPPPPPPPPPTTTTTT
			// SSSSSSSS********
			// fillBytesAfterPrefix is 6, so that the block becomes (before
			// encryption):
			// PPPPPPPPPP000000
			// TTTTTTSSSSSSSS**
			forgedPlainText := make([]byte, fillBytesAfterPrefix+len(plainText))
			copy(forgedPlainText[fillBytesAfterPrefix:], plainText)

			// Because we have added filler bytes, the oracle will return the
			// encryption a this block:
			// PPPPPPPPPP000000
			// TTTTTTSSSSSSSS**
			// As you can see, (prefix||filler) aligns with the block boundary.
			// By doing this, we have reduced the problem to the simpler
			// byte-at-a-time attack! Our chosen plain text will always start at the
			// beginning of a new block, thus allowing us to use the simpler attack
			// function that we implemented above.
			cipherText := ecbOracle(forgedPlainText)

			// All we have to do now, is stripping off the oracle's random prefix
			// (plus the filler) from the ciphertext before passing it back to the
			// simpler byte-at-a-time routine.
			return cipherText[prefixLen+fillBytesAfterPrefix:]
		})
	)
	// might as well use the smarter version :P
	return byteAtTimeAtk2(wrapperOracle)
}

// ecbEncryptionOracleWithPrefix returns an AES oracle that:
// - prepends a a random-length string of random bytes to the given plain text
// - appends a secret string to the given plain text
// then encrypts it all using AES ECB. That is:
// AES-ECB(random-prefix || plain-text|| secret, random-key)
// ecbEncryptionOracleWithSecret generates a random encryption key that the oracle
// will use to encrypt.
// Part of challenge 14 of set 2.
func ecbEncryptionOracleWithPrefix() (Oracle, error) {
	randPrefix, err := cpbytes.Random(0, 100)
	if err != nil {
		return nil, fmt.Errorf("generating random prefix: %s", err)
	}

	oracleWithSecret, err := ecbEncryptionOracleWithSecret()
	if err != nil {
		return nil, fmt.Errorf("creating oracle: %s", err)
	}

	oracle := func(plainText []byte) []byte {
		pp := make([]byte, len(randPrefix)+len(plainText))
		copy(pp, randPrefix)
		copy(pp[len(randPrefix):], plainText)

		return oracleWithSecret(pp)
	}

	return oracle, nil
}

// findPrefixLen finds and returns the length of the random string of random bytes
// that the given ecbOracle pre-pends to the plain text.
// Part of challenge 14 of set 2.
func findPrefixLen(blkSize int, ecbOracle Oracle) int {
	var prefixLen int
	// we leverage the fact that ECB is stateless and deterministic; the same 16 byte
	// plaintext block will always produce the same 16 byte ciphertext.
	// How? We feed increasing amounts of 0x00 until two identical ciphertext‐blocks
	// appear, which must be two 0x00‐blocks we injected just past the random prefix.
	// From that position you can back‐calculate exactly how many random bytes there
	// are.
	// Note that this solution assumes that the random string is truly random, i.e.,
	// it's encryption will not produce two equal ECB blocks.
	// For example:
	// R=random string, 0=our 0x00 bytes, S=secret that we want to decrypt,
	// *=padding after secret
	// RRRRRRRRRRSSSSSS
	// SS**************
	// We now ask the oracle to encrypt and increasing amount of 0x00.
	// The loop starts with fillBytes=blkSize*2, because we need at least two blocks
	// worth of 0x00s to produce two identical encrypted blocks.
	// After immediately adding the first 32 0x00, we
	// have:
	// RRRRRRRRRR000000
	// 0000000000000000
	// 0000000000SSSSSS
	// SS**************
	// Which does not produce two equal blocks, therefore we will exit the inner
	// loop.
	// From there, we keep adding 0x00 until we reach this point:
	// RRRRRRRRRR000000
	// 0000000000000000
	// 0000000000000000
	// SSSSSSSS********
	// And now, in the inner loop, we will have a match! In simple terms, we want to
	// align two 0x00‐blocks right after the random prefix.
	for fillBytes := blkSize * 2; ; fillBytes++ {
		var (
			cipherText = ecbOracle(make([]byte, fillBytes))
			prevBlk    = cipherText[:blkSize]
			nBlks      = len(cipherText) / blkSize
		)
		for blkIdx := 1; blkIdx < nBlks; blkIdx++ {
			var (
				blkStart = blkIdx * blkSize
				blkEnd   = blkStart + blkSize
			)
			if bytes.Equal(prevBlk, cipherText[blkStart:blkEnd]) {
				// To continue the explanation above, we are now here:
				// RRRRRRRRRR000000
				// 0000000000000000
				// 0000000000000000
				// SSSSSSSS********
				// How do we get the length of R?
				// Looking at it, it seems we could just do
				// blkSize-fillBytes_in_that_block = 16-6 = 10
				// But what if the random string spans multiple blocks? For example:
				// RRRRRRRRRRRRRRRR
				// RRRRRRRRRR000000
				// 0000000000000000
				// 0000000000000000
				// SSSSSSSS********
				// the count would be wrong. The length of the random string is the
				// sum of blocks it fills + its bytes at the current block!
				//
				// Let's try to compute all we need.
				// We remove blkSize*2 because these are the two identical blocks and
				// we don't need to take them into account.
				// The result of this is the number of 0x00s that are in the same
				// (last) block of the random string.
				// In this example, we would have:
				// 38-(16*2) = 38-32 = 6
				fillBytes -= blkSize * 2

				// now we compute the number of blocks that are positioned before the
				// two equal blocks. These are the number of blocks that the random
				// string occupies! For example:
				// blkIdx 0: RRRRRRRRRR000000
				// blkIdx 1: 0000000000000000
				// blkIdx 2: 0000000000000000
				// blkIdx 3: SSSSSSSS********
				// This if condition will be true at blkIdx=2.
				// Therefore, prevBlk is pointing to the block at blkIdx 1.
				// How many blocks are there before prevBlk? 1:
				// blkIdx-1 = 2-1 = 1
				//
				// Another example:
				// blkIdx 0: RRRRRRRRRRRRRRRR
				// blkIdx 1: RRRRRRRRRRRRRRRR
				// blkIdx 2: RRRRRRRRRR000000
				// blkIdx 3: 0000000000000000
				// blkIdx 4: 0000000000000000
				// blkIdx 5: SSSSSSSS********
				// This if condition will be true at blkIdx=4.
				// How many blocks are there before the two consecutive identical
				// blocks? 3:
				// blkIdx-1 = 4-1 = 3.
				randStrBlks := blkIdx - 1

				// Now that we know how many blocks the random string occupies, we
				// can compute its exact length. We know it must be at most
				// blkSize*randStrBlks
				// Butthe random string might not fill the last block. In the
				// examples above, the last block was always
				// RRRRRRRRRR000000
				// therefore doing blkSize*randStrBlks would also count the 0x00s
				// which is wrong. Then, we must remove the 0x00 from the total
				// count.
				// Using the last graphic example above, we have:
				// randStrBlks*blkSize - fillBytes = 3*16-6 = 42
				// which is the correct length of the random string!
				prefixLen = randStrBlks*blkSize - fillBytes
				return prefixLen
			}
			prevBlk = cipherText[blkStart:blkEnd]
		}
	}
}
