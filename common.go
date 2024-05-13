package main

import (
	crand "crypto/rand"
	"errors"
	mrand "math/rand/v2"
)

// aesWorker defines a type that performs an AES encryption/decryption
// operation on the given data, and returns the result of that operation.
type aesWorker func([]byte) []byte

// aesOracle defines a type that encrypts/decrypts a given plain/cipher text
// using AES.
type aesOracle func([]byte) ([]byte, error)

// xorBlocks takes two byte slices, b1 and b2, and returns a new byte slice
// containing the result of a byte-wise XOR operation between corresponding
// elements of b1 and b2
func xorBlocks(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, errors.New("input blocks are of different lengths")
	}

	xored := make([]byte, len(b1))
	for i := range xored {
		xored[i] = b1[i] ^ b2[i]
	}

	return xored, nil
}

// randomBytes generates returns a slice of size min <= x <= max (chosen
// randomly) filled with random bytes.
func randomBytes(min, max int) ([]byte, error) {
	var (
		nBytes = mrand.IntN(max-min+1) + min
		buf    = make([]byte, nBytes)
	)
	if _, err := crand.Read(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// delPadPkcs7String is a wrapper of delPadPkcs7 for string data.
func delPadPkcs7String(data string) string {
	return string(delPadPkcs7([]byte(data)))
}

// delPadPkcs7 deletes PKCS#7 padding from data.
// This is a necessary step after decryption of an AES cipher text because AES
// always adds padding before encrypting a plain text.
// If the plaintext is exactly a multiple of the block size, without adding an
// extra block of padding, the decryption process would not be able to
// distinguish whether the last block is part of the plaintext or padding.
// By always adding an additional block of padding, the decrypted message
// clearly indicates the presence of padding bytes, which can be correctly
// removed.
func delPadPkcs7(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	pad := int(data[len(data)-1])
	return data[:len(data)-pad]
}
