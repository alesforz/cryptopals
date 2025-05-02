package cpaes

import (
	"bytes"
	"crypto/aes"
	"slices"

	"github.com/alesforz/cryptopals/cppad"
)

// profileFor returns the encoding of a user formatted as a URL query.
// e.g., given email "foo@bar.com", it returns
// "email=foo@bar.com&uid=10&role=user"
func profileFor(email []byte) []byte {
	if bytes.ContainsAny(email, "&=") {
		panic("email address; can't contain '&' or '=' characters")
	}

	return slices.Concat([]byte("email="), email, []byte("&uid=10&role=user"))
}

// parseProfile parses a profile cookie and returns a map of the key-value pairs.
func parseProfile(cookie []byte) map[string]string {
	profile := make(map[string]string, 3)
	for _, part := range bytes.Split(cookie, []byte{'&'}) {
		kv := bytes.Split(part, []byte{'='})
		if len(kv) != 2 {
			panic("invalid profile cookie")
		}
		profile[string(kv[0])] = string(kv[1])
	}
	return profile
}

// cutAndPasteAtk is an attack that allows us to cut and paste blocks of ciphertext
// to create a new ciphertext that decrypts to a different profile.
// It works by exploiting the fact that the ECB mode of operation encrypts each block
// independently.
func cutAndPasteAtk(ECBEncOracle, ECBDecOracle Oracle) []byte {
	var (
		// This email generates a ciphertext with the following blocks:
		// block 0: email=foooo@bar.
		// block 1: com&uid=10&role=
		// block 2: user + padding
		// Notice how 'role=' is aligned with the start of the next block.
		user1       = []byte("foooo@bar.com")
		profile1    = profileFor(user1)
		cipherText1 = ECBEncOracle([]byte(profile1))

		// This email generates a ciphertext with the following blocks:
		// block 0: email=foooo@bar.
		// block 1: adminXXXXXXXXXXX  <- XX is padding we add to the email
		// block2:  &uid=10&role=use
		// block 2: r + padding
		// Notice how 'admin' is aligned with the start of the block.
		user2 = slices.Concat(
			[]byte("foooo@bar."),
			cppad.PKCS7([]byte("admin"), aes.BlockSize),
		)
		profile2    = profileFor(user2)
		cipherText2 = ECBEncOracle([]byte(profile2))
	)
	// We can now compose a cipher text which will decrypt to an admin user
	// by copying and pasting blocks of the two different cipher texts:
	// block 0: email=foooo@bar.   from cipherText1
	// block 1: com&uid=10&role=   from cipherText1
	// block 2: adminXXXXXXXXXXX   from cipherText2
	adminCipherText := slices.Concat(cipherText1[:32], cipherText2[16:32])

	return cppad.RemovePKCS7(ECBDecOracle(adminCipherText))
}
