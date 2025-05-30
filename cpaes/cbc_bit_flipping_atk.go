package cpaes

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/alesforz/cryptopals/cpbytes"
	"github.com/alesforz/cryptopals/cpxor"
)

// cbcBitFlippingAtk implements a bit flipping attack on a cipher text encrypted
// using AES CBC. In a bit flipping attack, the attacker can change the ciphertext
// in such a way as to result in a predictable change of the plaintext.
// In this challenge, the attack consists in modifying the cipher text so that its
// decryption contains the string ";admin=true;".
// Solves challenge 16 of set 2.
func cbcBitFlippingAtk(encOracle, decOracle Oracle) []byte {
	var (
		// we give 2 blocks as plain text to ther oracle.
		fillerBlks = make([]byte, 32)
		cipherText = encOracle(fillerBlks)

		// the string is what we want except we re-use the ';' at the beginning of
		// the suffix string as the ';' we need after 'true'
		atkText = []byte("00000;admin=true")

		// the starting index of the block we want to attack in the cipher text
		prevCtBlkStartIdx = 32
	)
	// During decryption, CBC does:
	// cipherText_(i-1)^(cipherText_(i_1)^plainText_i)=plaintext_i
	//
	// That is, the current block of plain text is the result of doing:
	// (prev_ciphertext_block) XOR (prev_ciphertext_block XOR curr_plain_text_block)
	// where (prev_ciphertext_block XOR curr_plain_text_block) is the decryption of
	// the current cipher text block.
	//
	// The goal is to change the cipher text so that the decryption puts the tuple
	// ;admin=true; in the plaintext.
	// in the equation above:
	// - cipherText_(i-1) is what we have
	// - (cipherText_(i-1)^plainText_i) is what the decryption function produces
	// so, really, what we have to do, is change the cipher text so that its XOR with
	// (cipherText_(i-1)^plainText_i)=the byte we want.
	// In the following loops we do exactly that: we search for the byte that XORed
	// with (cipherText^plainText) at pos i gives us the byte we want. Then we sub
	// that byte in the cipher text.
	for i := range aes.BlockSize {
		for b := range 256 {
			// for example, we want to place the first ';' into place.
			// we know the plain text (our filler blocks) at position i=5 has the
			// byte 0x00=48 ASCII (actually, it's all 0s).
			// We want the decryption to place the ';'=59 in that position instead
			// of 0x00. So we search for the byte that XORed with
			// (cipherText[32+5] XOR 48)=59
			// The same reasoning applies to all the bytes of the atkText.
			if cipherText[prevCtBlkStartIdx+i]^fillerBlks[i]^byte(b) == atkText[i] {
				cipherText[prevCtBlkStartIdx+i] = byte(b)
				break
			}
		}
	}

	return decOracle(cipherText)
}

// cbcOraclesWithAffix creates two oracles that do AES CBC encryption and decryption
// on their inputs respectively.
// The encryption oracle does some additional operations before encrypting its input
// using AES CBC:
// - prepend the fixed string "comment1=cooking%20MCs;userdata=" to the plain text.
// - append the fixed string ";comment2=%20like%20a%20pound%20of%20bacon" to the
// plain text
// - quote out any ';' or '=' characters in the plain text
//
// Part of Challenge 16 of set 2.
func cbcOraclesWithAffix() (enc, dec Oracle, _ error) {
	const (
		prefix = "comment1=cooking%20MCs;userdata="
		suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
	)

	iv, err := cpbytes.Random(aes.BlockSize, aes.BlockSize)
	if err != nil {
		return nil, nil, fmt.Errorf("generating random IV: %s", err)
	}

	key, err := cpbytes.Random(aes.BlockSize, aes.BlockSize)
	if err != nil {
		return nil, nil, fmt.Errorf("generating random AES key: %s", err)
	}

	var (
		prefLen = len(prefix)
		sufLen  = len(suffix)
	)
	enc = func(plainText []byte) []byte {
		plainText = bytes.ReplaceAll(plainText, []byte{';'}, []byte("%3B"))
		plainText = bytes.ReplaceAll(plainText, []byte{'='}, []byte("%3D"))

		var (
			textLen            = len(plainText)
			plainTextWithAffix = make([]byte, prefLen+textLen+sufLen)
		)
		copy(plainTextWithAffix, prefix)
		copy(plainTextWithAffix[prefLen:], plainText)
		copy(plainTextWithAffix[prefLen+textLen:], suffix)

		cipherText, err := encryptCBC(iv, plainTextWithAffix, key)
		if err != nil {
			panic(err)
		}

		return cipherText
	}

	dec = func(cipherText []byte) []byte {
		plainText, err := decryptCBC(iv, cipherText, key)
		if err != nil {
			panic(err)
		}

		return plainText
	}

	return enc, dec, nil
}

// cbcBitFlippingAtk2 implements a smarter, faster version of the CBC bit flipping
// attack we implemented in the cbcBitFlippingAtk function above.
// This solution is twice as fast as the one in cbcBitFlippingAtk.
// Solves Challenge 16 of set 2.
func cbcBitFlippingAtk2(encOracle, decOracle Oracle) []byte {
	var (
		// we give 2 blocks as plain text to ther oracle.
		fillerBlks = make([]byte, 32)

		// we get the encryption of:
		// blk 1: PPPPPPPPPPPPPPPP
		// blk 2: PPPPPPPPPPPPPPPP
		// blk 3: 0000000000000000
		// blk 4: 0000000000000000
		// blk 5: SSSSSSSSSSSSSSSS
		// blk 6: SSSSSSSSSSSSSSSS
		// where P=prefix, S=suffix
		cipherText = encOracle(fillerBlks)

		// the string is what we want except we re-use the ';' at the beginning of
		// the suffix string as the ';' we need after 'true'
		// we want to put this block in place of blk 4 above.
		atkText = []byte("00000;admin=true")
	)
	// This will give us: (00000;admin=true XOR 0000000000000000)
	atkBlk, _ := cpxor.Blocks(atkText, fillerBlks[:16])

	// oldPrevCtBlk is blk 3 above.
	oldPrevCtBlk := cipherText[32:48]

	// This will give us:
	// (0000000000000000 XOR atkBlk), which is equal to:
	// (blk3 XOR (00000;admin=true XOR 0000000000000000))
	// ...
	newPrevCtBlk, _ := cpxor.Blocks(oldPrevCtBlk, atkBlk)

	// ... which we put in the cipher text instead of blk 3
	copy(oldPrevCtBlk, newPrevCtBlk)

	// the plain text of blk 4 is the calculated as:
	//  dec(blk4) XOR blk3
	// = dec(cipherText[48:64]) XOR cipherText[32:48]
	// = (pt4 XOR oldPrevCtBlk) XOR newPrevCtBlk
	// = (pt4 XOR oldPrevCtBlk) XOR (oldPrevCtBlk XOR atkBlk)
	// = pt4 XOR oldPrevCtBlk XOR oldPrevCtBlk XOR atkBlk
	// = pt4 XOR atkBlk
	// = fillerBlks[16:32] XOR (atkText XOR fillerBlks[:16])
	// = 0000000000000000 XOR atkText XOR 0000000000000000
	// = atkText
	// = "00000;admin=true"
	return decOracle(cipherText)
}
