// Code in this file solves challenge 17 of set 3 of the Cryptopals.
package cpaes

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/alesforz/cryptopals/cpbytes"
	"github.com/alesforz/cryptopals/cppad"
	"github.com/alesforz/cryptopals/cpxor"
)

// paddingOracleAtkTools collects the pieces needed to mount the CBC padding
// oracle attack: the two oracles wired with the same random key and IV, the
// IV itself, and the list of candidate plain texts from which the oracle will
// pick one at random.
type paddingOracleAtkTools struct {
	encryptionOracle Oracle
	decryptionOracle Oracle
	plainTexts       []string
	iv               []byte
}

// cbcPaddingOracleAtk performs a CBC padding oracle attack on the given
// encryption oracle. It recovers the plain text corresponding to the cipher
// text produced by the oracle, without knowing the encryption key. The
// returned plain text includes the PKCS#7 padding added during encryption.
// Solves challenge 17 of set 3.
func cbcPaddingOracleAtk(atkTools paddingOracleAtkTools) ([]byte, error) {
	var (
		blkSize = aes.BlockSize
		prevBlk = atkTools.iv

		// recall that encOracle ignores its input
		cipherText = atkTools.encryptionOracle([]byte{})
		plainText  = make([]byte, 0, len(cipherText))
	)

	cipherTextBlks, err := cpbytes.ToChunks(cipherText, blkSize)
	if err != nil {
		return nil, fmt.Errorf("attack failed: chunking cipher text: %s", err)
	}

	for blk := range cipherTextBlks {
		var (
			myIV          = make([]byte, blkSize)
			cipherTextBlk = cipherTextBlks[blk]
		)
		// Recover the result of decrypting the current cipher text block before
		// CBC's XOR with the previous cipher text block.
		recoveredXoredBlk := paddingOracleAtkBlk(
			myIV,
			cipherTextBlk,
			atkTools.decryptionOracle,
		)

		// CBC decryption does: plainText_i = decrypt(cipherText_i) XOR prevBlk.
		plainTextBlk, err := cpxor.Blocks(prevBlk, recoveredXoredBlk)
		if err != nil {
			return nil, fmt.Errorf("atk failed: %s", err)
		}

		// add recovered plain text block to the whole plain text we are
		// reconstructing
		plainText = append(plainText, plainTextBlk...)

		// update prevBlk
		prevBlk = cipherTextBlk
	}

	return plainText, nil
}

// newPaddingOracleAtkTools initializes the random IV and AES key used by the
// padding oracle challenge, along with the matching encryption and decryption
// oracles. The encryption oracle ignores its input and encrypts one of the
// base64-encoded plain texts chosen at random. The decryption oracle expects
// the IV to be prepended to the cipher text it receives.
func newPaddingOracleAtkTools() paddingOracleAtkTools {
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
		decoded   = make([]byte, base64.StdEncoding.DecodedLen(len(plainText)))
	)
	_, err = base64.StdEncoding.Decode(decoded, plainText)
	if err != nil {
		panic(fmt.Sprintf("decoding chosen plain text from Base64: %s", err))
	}

	encryptOracle := func(_ []byte) []byte {
		// encrypts one of the randomly chosen plain texts thus ignores its input
		cipherText, err := encryptCBC(iv, decoded, key)
		if err != nil {
			panic(err)
		}
		return cipherText
	}

	decryptOracle := func(cipherText []byte) []byte {
		// expects IV to be pre-pended to cipher text
		iv := cipherText[:blkSize]
		plainText, err := decryptCBC(iv, cipherText[blkSize:], key)
		if err != nil {
			panic(err)
		}
		return plainText
	}

	tools := paddingOracleAtkTools{
		encryptionOracle: encryptOracle,
		decryptionOracle: decryptOracle,
		plainTexts:       plainTexts,
		iv:               iv,
	}

	return tools
}

// paddingOracleAtkBlk recovers the AES decryption of a single CBC cipher text
// block by manipulating the IV bytes and checking whether the oracle reports a
// valid PKCS#7 padding. It returns the decrypted block, which still needs to be
// xored with the real previous cipher text block to obtain the actual plain
// text.
func paddingOracleAtkBlk(iv, cipherTextBlk []byte, decryptOracle Oracle) []byte {
	var (
		blkSize      = aes.BlockSize
		recoveredBlk = make([]byte, blkSize)
	)
	// padBytes=1 0000000000000000
	// padBytes=2 0000000000000002
	// padBytes=3 0000000000000033
	// ...
	for padBytes := 1; padBytes <= blkSize; padBytes++ {
		guessIdx := blkSize - padBytes
		// Walk bytes from the end of the block to the start, brute-forcing the
		// value that makes the padding valid for the current pad length.
		for b := range 256 {
			// e.g., the first round of the outer loop, we modify the last byte of iv
			// until the decryption oracle tells us the padding of the decrypted
			// plain text block [p1p2..pN] is valid (i.e., equals to 0x01).
			// so we try all the possible byte values (0-255) for that byte:
			//
			//            | we are changing this byte
			//            v
			// [iv1iv2...ivN]     [c1c2...cN]
			//       |                 |
			//       |           Decrypt([c1c2..cN])
			//       |                 |
			//       |         	  [d1d2...dN]
			//       |				   |
			//       |-------XOR-------|
			//                |
			//  	    [p1p2...pN]
			//                   ^
			//				     |	until this byte equals 0x01
			//
			// We'll keep doing this for each byte of the IV.
			iv[guessIdx] = byte(b)
			// recall that the decryption oracle expects IV to be pre-pended to
			// cipher text
			toDecrypt := slices.Concat(iv, cipherTextBlk)
			forgedPlainTextBlk := decryptOracle(toDecrypt)

			_, hasValidPad := validatePadding(forgedPlainTextBlk)
			if hasValidPad {
				// we found the byte that produces the desired padding length.
				// Now we can recover the corresponding byte of the block that CBC
				// decryption produces before xoring it with the previous cipher
				// text block (out IV). That is:
				// [iv1iv2...ivN]     [c1c2...cN]
				//       |                 |
				//       |           Decrypt([c1c2..cN])
				//       |                 |
				//       |         	  [d1d2...dN]  <--- we are recovering this block
				//       |				   |
				//       |-------XOR-------|
				//                |
				//  	      [p1p2...pN]  <- actual plain text block, we are doing
				//                            the shenanigans on the IV so that
				//                            p1, p2, ... pN, are set to the desired
				//                            padding length.
				//
				recoveredBlk[guessIdx] = byte(b) ^ byte(padBytes)
				break
			}
		}
		// Prepare the IV for the next round so that the bytes already found keep
		// producing the right padding length when we guess the next byte.
		for v := blkSize - 1; v >= guessIdx; v-- {
			// e.g., we have guessed the last byte of the block [d1d2..dN] we want
			// to recover. We now want to guess the 2nd to last byte. Therefore, we
			// need to adjust the last bytes of the IV so that they produce
			// padding length 0x02 when xored with the already recovered bytes of
			// the decrypted block.
			// If the last byte of the decrypted block is dN, we know that:
			// ivN ^ dN = 0x01
			// dN = 0x01 ^ ivN
			// That is:
			// [iv1iv2...ivN]     [c1c2...cN]
			//       |                 |
			//       |           Decrypt([c1c2..cN])
			//       |                 |
			//       |         	  [d1d2...dN]
			//       |				   |
			//       |-------XOR-------|
			//                |
			//  	    [p1p2...0x01]
			//
			// Now we need to adjust ivN so that:
			// [iv1iv2...ivN]     [c1c2...cN]
			//       |                 |
			//       |           Decrypt([c1c2..cN])
			//       |                 |
			//       |         	  [d1d2...dN]
			//       |				   |
			//       |-------XOR-------|
			//                |
			//  	    [p1p2...0x02]
			//
			// ivN' ^ dN = 0x02  => ivN' = 0x02 ^ dN => ivN' = 0x02 ^ (0x01 ^ ivN)
			//
			// Therefore:
			// ivN' = ivN ^ (0x01 ^ 0x02)
			//
			iv[v] ^= (byte(padBytes) ^ byte(padBytes+1))
		}
		// Now in the next round of the outer loop, we'll try to guess the 2nd to
		// last byte of the IV that will produce 0x02 in position N-1 of the
		// plain text:
		//           | we'll change this byte
		//           v
		// [iv1iv2..ivN-1|ivN']     [c1c2...cN]
		//       |                       |
		//       |                 Decrypt([c1c2..cN])
		//       |                       |
		//       |         	       [d1d2...dN-1|dN]
		//       |				         |   ^
		//       |----------XOR----------|   | the next byte we want to recover
		//                   |
		//  	       [p1p2...pN-1|0x02]
		//                       ^
		//				         |	until this byte equals 0x02
		// and so on...
	}
	// the calling function now will have [d1d2...dN], which it will xor with
	// the real previous cipher text block to obtain the actual plain text block
	// [p1p2...pN].
	return recoveredBlk
}

// validatePadding checks whether the plain text ends with valid PKCS#7 padding
// and returns the unpadded plain text together with a flag indicating whether
// the padding was correct.
// If the padding is incorrect, the returned []byte slice is equivalent to the
// input plainText.
func validatePadding(plainText []byte) ([]byte, bool) {
	unpadded, err := cppad.RemovePKCS7(plainText)
	if err != nil {
		return unpadded, false
	}

	return unpadded, true
}
