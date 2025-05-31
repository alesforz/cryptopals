package cpaes

import (
	"crypto/aes"
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/alesforz/cryptopals/cpbytes"
	"github.com/alesforz/cryptopals/cppad"
	"github.com/alesforz/cryptopals/cpxor"
)

func cbcPaddingOracleAtk() ([]byte, error) {
	var (
		origIV, encOracle, decOracle = makePaddingOracleAtkOracles()
		blkSize                      = aes.BlockSize
		recoveredXoredBlk            = make([]byte, blkSize)
		prevBlk                      = origIV

		// recall that encOracle ignores its input
		cipherText = encOracle([]byte{})
		plainText  = make([]byte, 0, len(cipherText))
	)

	cipherTextBlks, err := cpbytes.BytesToChunks(cipherText, blkSize)
	if err != nil {
		return nil, fmt.Errorf("attack failed: chunking cipher text: %s", err)
	}

	for blk := range cipherTextBlks {
		// padBytes=1 0000000000000000
		// padBytes=2 0000000000000002
		// padBytes=3 0000000000000033
		myIV := make([]byte, blkSize)
		for padBytes := 1; padBytes <= blkSize; padBytes++ {
			guessIdx := blkSize - padBytes
			for b := range 256 {
				myIV[guessIdx] = byte(b)
				// recall that the decryption oracle expects IV to be pre-pended to
				// cipher text
				ct := slices.Concat(myIV, cipherTextBlks[blk])
				forgedPlainTextBlk := decOracle(ct)

				_, hasValidPad := validatePadding(forgedPlainTextBlk)
				if hasValidPad {
					// plainText[guessIdx] is set to the correct padding value (==i)
					// fmt.Println(
					// 	"i:", padBytes,
					// 	"b:", b,
					// 	"pt:", forgedPlainTextBlk[guessIdx],
					// )
					recoveredXoredBlk[guessIdx] = byte(b) ^ byte(padBytes)
					break
				}
			}
			// prepare myIV for next round
			for v := blkSize - 1; v >= guessIdx; v-- {
				// bytes should be set so that plain text bytes from last to next
				// guessIdx will be set to the next pad length.
				myIV[v] ^= (byte(padBytes) ^ byte(padBytes+1))
			}
		}

		plainTextBlk, err := cpxor.Blocks(prevBlk, recoveredXoredBlk)
		if err != nil {
			return nil, fmt.Errorf("atk failed: %s", err)
		}

		// add recovered plain text block to the whole plain text we are
		// reconstructing
		plainText = append(plainText, plainTextBlk...)

		// update prevBlk
		prevBlk = cipherTextBlks[blk]
	}

	return plainText, nil
}

func makePaddingOracleAtkOracles() ([]byte, Oracle, Oracle) {
	blkSize := aes.BlockSize

	iv, err := cpbytes.Random(uint(blkSize), uint(blkSize))
	if err != nil {
		panic(fmt.Sprintf("generating random IV: %s", err))
	}

	key, err := cpbytes.Random(uint(blkSize), uint(blkSize))
	if err != nil {
		panic(fmt.Sprintf("generating random key: %s", err))
	}

	var (
		// base64 encoded
		plainTexts = []string{
			"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
			"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
			"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
			"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
			"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
			"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
			"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
			"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
			"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
			"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
		}
		idx       = rand.IntN(len(plainTexts))
		plainText = []byte(plainTexts[idx])
	)

	encOracle := func(_ []byte) []byte {
		//  encrypts one of the randomly chosen plain texts thus ignores its input
		cipherText, err := encryptCBC(iv, plainText, key)
		if err != nil {
			panic(err)
		}
		return cipherText
	}

	decOracle := func(cipherText []byte) []byte {
		// expects IV to be pre-pended to cipher text
		iv := cipherText[:blkSize]
		plainText, err := decryptCBC(iv, cipherText[blkSize:], key)
		if err != nil {
			panic(err)
		}
		return plainText
	}

	return iv, encOracle, decOracle
}

func validatePadding(plainText []byte) ([]byte, bool) {
	unpadded, err := cppad.RemovePKCS7(plainText)
	if err != nil {
		return unpadded, false
	}

	return unpadded, true
}
