// Code in this file is an alternative implementation of the byte-at-a-time attack
// that I found in the wild. It's a smarter solution, and is about 18% faster than
// the other one (less memory usage, too).
// This is a port of the original solution in Python.
package cpaes

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
)

// byteAtTimeAtk2 implements a byte-at-a-time decryption attack, aka padding oracle
// attack.
// It decrypts a secret by iteratively guessing each byte of the plain text.
// It first crafts plain texts, then asks the oracle to encrypt them, and finally
// compares the resulting cipher text blocks to the target cipher text.
// This sort of input manipulation allows it to deduce each byte of the secret one
// at a time, thus reconstructing it without needing the encryption key.
// This method exploits the deterministic nature of block ciphers and the feedback
// from the oracle to reveal the hidden data.
// Challenge 12 of set 2.
func byteAtTimeAtk2(ECBOracle Oracle) ([]byte, error) {
	blkSize, secretLen := findECBBlockSizeAndSuffixLength(ECBOracle)
	fmt.Println("block size:", blkSize)
	fmt.Println("suffix length:", secretLen)

	if blkSize != aes.BlockSize {
		const formatStr = "block size %d is not equal to AES block size %d"
		return nil, fmt.Errorf(formatStr, blkSize, aes.BlockSize)
	}

	testBuf := make([]byte, blkSize*2)
	if !detectECB(ECBOracle(testBuf)) {
		return nil, fmt.Errorf("oracle doesn't encrypt with AES ECB")
	}

	// Example: the secret is "YELLOWSUN", length 9
	// cipherTexts = [
	//     pad=15, [000000000000000Y | ELLOWSUN********]
	//     pad=14, [00000000000000YE | LLOWSUN*********]
	//     pad=13, [0000000000000YEL | LOWSUN**********]
	//     pad=12, [000000000000YELL | OWSUN***********]
	//     pad=11, [00000000000YELLO | WSUN************]
	//     pad=10, [0000000000YELLOW | SUN*************]
	//     pad=9,  [000000000YELLOWS | UN**************]
	//     pad=8,  [00000000YELLOWSU | N***************]
	//     pad=7,  [0000000YELLOWSUN]
	//     pad=6,  [000000YELLOWSUN*]
	//     pad=5,  [00000YELLOWSUN**]
	//     pad=4,  [0000YELLOWSUN***]
	//     pad=3,  [000YELLOWSUN****]
	//     pad=2,  [00YELLOWSUN*****]
	//     pad=1,  [0YELLOWSUN******]
	//     pad=0,  [YELLOWSUN*******]
	// ]
	// pad is the characters that we feed to the oracle to generate the cipher text.
	// Recall that the oracle will append the secret immediately after the data we
	// provide.
	//  * means any other character after the secret that we don't care about
	cipherTexts, err := makeCipherTexts(blkSize, ECBOracle)
	if err != nil {
		return nil, fmt.Errorf("making cipher texts: %s", err)
	}

	var (
		// transposed = [
		//    000000000000000Y, 00000000000000YE, 0000000000000YEL, 000000000000YELL,
		//    00000000000YELLO, 0000000000YELLOW, 000000000YELLOWS, 00000000YELLOWSU,
		//    0000000YELLOWSUN, 000000YELLOWSUN*, 00000YELLOWSUN**, 0000YELLOWSUN***,
		//    000YELLOWSUN****, 00YELLOWSUN*****, 0YELLOWSUN******, YELLOWSUN*******
		// ]
		transposed = transposeAndFlattenBlocks(cipherTexts)

		// blksToAttack = [
		//   000000000000000Y,
		//   00000000000000YE,
		//   0000000000000YEL,
		//   000000000000YELL,
		//   00000000000YELLO,
		//   0000000000YELLOW,
		//   000000000YELLOWS,
		//   00000000YELLOWSU,
		//   0000000YELLOWSUN,
		// ]
		// That is, we have the only blocks we need to recover the secret. Notice how
		// they are aligned with the next byte of the secret that we want to recover.
		blksToAttack = transposed[:secretLen]

		// secret starts as a 15-byte slice of zeroes.
		secret = make([]byte, blkSize-1, secretLen+(blkSize-1))
	)
	for _, blk := range blksToAttack {
		// we feed to the oracle the last 15 bytes of the secret we have recovered
		// so far. Notice how, after each iteration, they resemble the blocks in
		// blksToAttack.
		prefix := secret[len(secret)-(blkSize-1):]

		// What the above means, graphically:
		// i=0, prefix=000000000000000, blk=000000000000000Y, guess=Y
		// i=1, prefix=00000000000000Y, blk=00000000000000YE, guess=E
		// i=2, prefix=0000000000000YE, blk=0000000000000YEL, guess=L
		// i=3, prefix=000000000000YEL, blk=000000000000YELL, guess=L
		// i=4, prefix=00000000000YELL, blk=00000000000YELLO, guess=O
		// i=5, prefix=0000000000YELLO, blk=0000000000YELLOW, guess=W
		// i=6, prefix=000000000YELLOW, blk=000000000YELLOWS, guess=S
		// i=7, prefix=00000000YELLOWS, blk=00000000YELLOWSU, guess=U
		// i=8, prefix=0000000YELLOWSU, blk=0000000YELLOWSUN, guess=N
		// reconstructed secret = YELLOWSUN
		// prefix is always 15 bytes long
		guessedByte := guessByte2(prefix, blk, ECBOracle)

		secret = append(secret, guessedByte)

		// uncomment to see decryption byte by byte
		// fmt.Printf("%q\n", secret[blkSize-1:])
		// time.Sleep(100 * time.Millisecond)
	}

	return secret[blkSize-1:], nil
}

// makeCipherTexts creates a list of cipher texts, each split into blocks of the
// given block size. It uses the provided oracle to generate the cipher texts.
// Part of challenge 12 of set 2.
func makeCipherTexts(blkSize int, oracle Oracle) ([][][]byte, error) {
	if blkSize <= 0 {
		return nil, errors.New("block size must be greater than 0")
	}
	if oracle == nil {
		return nil, errors.New("oracle must not be nil")
	}

	var (
		cipherTexts = make([][][]byte, blkSize)
		err         error
	)
	for i := range cipherTexts {
		forgedCipherText := oracle(make([]byte, blkSize-i-1))
		cipherTexts[i], err = bytesToChunks(forgedCipherText, blkSize)
		if err != nil {
			const errStr = "splitting forged cipher text %d into blocks: %s"
			return nil, fmt.Errorf(errStr, i, err)
		}
	}

	return cipherTexts, nil
}

// bytesToChunks splits the input data into chunks of the specified size.
// It expects the length of the input data to be a multiple of the chunk size.
// It returns a slice of byte slices, where each slice represents a chunk of the
// input data.
// It does not modify the input slice.
// Part of challenge 12 of set 2.
func bytesToChunks(data []byte, chunkSize int) ([][]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	if chunkSize <= 0 {
		return nil, errors.New("chunk size must be greater than 0")
	}
	if len(data)%chunkSize != 0 {
		return nil, errors.New("data length is not a multiple of chunk size")
	}

	var (
		// In AES ECB we expect the data to be a multiple of the block size, so this
		// division should be exact.
		nChunks = len(data) / chunkSize
		chunks  = make([][]byte, 0, nChunks)
	)
	for i := 0; i < len(data); i += chunkSize {
		// no need to check for a smaller last chunk, because in ECB all chunks have
		// the same size.
		chunkEnd := i + chunkSize
		chunks = append(chunks, data[i:chunkEnd])
	}

	return chunks, nil
}

// transposeAndFlattenBlocks transposes the chunks of the given blocks and flattens
// them into a single slice of byte slices.
// In the context of the byte-at-a-time attack, blocks stores some cipher texts split
// into chunks of the same size (16 bytes).
// The function works like 'zip' in other languages, that is, it only iterates over
// the smallest slice of blocks.
// For example:
//
// blocks = [ [ c1 | c2 | c3 ], [ c4 | c5 | c6 ], [ c7 | c8 | c9 ], [ c10 | c11 ] ]
// where 'c' stands for chunk
//
// returns:
// result = [ c1, c4, c7, c10, c2, c5, c8, c11 ]
//
// transposeAndFlattenBlocks does not modify the input slices.
func transposeAndFlattenBlocks(blocks [][][]byte) [][]byte {
	chunksPerBlk := len(blocks[0])
	// find the minimum number of chunks per block because the next loop will only
	// run over the smallest slice of blocks.
	for _, block := range blocks {
		chunksPerBlk = min(chunksPerBlk, len(block))
	}

	result := make([][]byte, 0, chunksPerBlk*len(blocks))
	for i := range chunksPerBlk {
		for j := range len(blocks) {
			result = append(result, blocks[j][i])
		}
	}

	return result
}

// guessByte brute-forces a single unknown byte of the secret by comparing the
// oracle's outputs for all 256 possible byte values against a target ciphertext
// block.
// prefix must be a block of length 15 (i.e., block size - 1) so that it can be
// concatenated with the guess byte to form a 16-byte plaintext block to feed to the
// oracle.
// targetBlk is the ciphertext block (16 bytes) we aim to reproduce by encrypting
// [prefix|guessByte].
//
// guessByte returns the correctly guessed secret byte (0–255), or panics if no match
// is found.
// guessByte does not modify the input slices.
// Part of challenge 12 of set 2.
func guessByte2(prefix, targetBlk []byte, oracle Oracle) byte {
	var (
		blkSize   = len(targetBlk)
		forgedBlk = make([]byte, blkSize)
	)
	copy(forgedBlk, prefix)

	for i := range 255 {
		guessByte := byte(i)

		forgedBlk[len(forgedBlk)-1] = guessByte

		cipherText := oracle(forgedBlk)
		if bytes.Equal(cipherText[:blkSize], targetBlk) {
			return guessByte
		}
	}

	panic("couldn't guess the byte of the cipher text")
}
