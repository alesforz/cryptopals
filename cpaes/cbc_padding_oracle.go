package cpaes

import (
	"crypto/aes"
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/alesforz/cryptopals/cpbytes"
	"github.com/alesforz/cryptopals/cppad"
)

func cbcPaddingOracleAtk() error {
	encOracle, decOracle, err := makePaddingOracleAtkOracles()
	if err != nil {
		return fmt.Errorf("attack failed: %s", err)
	}

	var (
		blkSize           = aes.BlockSize
		myIV              = make([]byte, blkSize)
		recoveredXoredBlk = make([]byte, blkSize)

		// recall that encOracle ignores its input
		cipherText = encOracle([]byte{})
	)

	cipherTextBlks, err := bytesToChunks(cipherText, blkSize)
	if err != nil {
		return fmt.Errorf("attack failed: chunking cipher text: %s", err)
	}

	// i=1 0000000000000000
	// i=2 0000000000000002
	// i=3 0000000000000033
	for i := 1; i <= blkSize; i++ {
		guessIdx := blkSize - i
		for b := range 256 {
			myIV[guessIdx] = byte(b)

			// recall that the decryption oracle expects IV to be pre-pended to
			// cipher text
			ct := slices.Concat(myIV, cipherTextBlks[0])
			plainText := decOracle(ct)

			_, hasValidPad := validatePadding(plainText)
			if hasValidPad {
				// plainText[guessIdx] is set to the correct padding value (==i)
				fmt.Println("i:", i, "b:", b, "pt:", plainText[guessIdx])
				recoveredXoredBlk[guessIdx] = byte(b) ^ byte(i)
				break
			}
		}
		// prepare myIV for next round
		for v := blkSize - 1; v >= guessIdx; v-- {
			// bytes should be set so that plain text bytes from last to next
			// guessIdx will be set to the next pad length.
			myIV[v] = byte(i + 1)
		}
	}

	fmt.Println("recovered:", recoveredXoredBlk)
	fmt.Println("myIV:", myIV)

	return nil
}

func makePaddingOracleAtkOracles() (Oracle, Oracle, error) {
	blkSize := aes.BlockSize

	iv, err := cpbytes.Random(uint(blkSize), uint(blkSize))
	if err != nil {
		return nil, nil, fmt.Errorf("generating random IV: %s", err)
	}

	key, err := cpbytes.Random(uint(blkSize), uint(blkSize))
	if err != nil {
		return nil, nil, fmt.Errorf("generating random IV: %s", err)
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

	return encOracle, decOracle, nil
}

func validatePadding(plainText []byte) ([]byte, bool) {
	unpadded, err := cppad.RemovePKCS7(plainText)
	if err != nil {
		return unpadded, false
	}

	return unpadded, true
}
