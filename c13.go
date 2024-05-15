package main

import (
	"errors"
	"math/rand"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// profileFor returns the encoding of a user formatted as a URL query.
// e.g., given email "foo@bar.com", it returns
// "email=foo@bar.com&role=user&uid=10"
func profileFor(email string) (string, error) {
	if strings.ContainsAny(email, "&=") {
		const errMsg = "invalid email address; can't contain '&' or '=' characters"
		return "", errors.New(errMsg)
	}

	v := url.Values{}
	v.Set("email", email)

	// ID: 10 to 99
	v.Add("uid", strconv.Itoa(10+rand.Intn(90)))

	v.Add("role", "user")

	return v.Encode(), nil
}

func createAdminProfile(
	encryptionOracle aesOracle,
	adminOracle func([]byte) (bool, error),
) (bool, error) {

	// This email generate a ciphertext with the following blocks:
	// block 0: email=foo%40bar.
	// block 1: aaaaaaacom&role=
	// block 2: user&uid=42 + padding
	const forgedUserEmail = "foo@bar.aaaaaaaaaa"
	forgedUser, err := encryptionOracle([]byte(forgedUserEmail))
	if err != nil {
		return false, err
	}

	// This email generate a ciphertext with the following blocks:
	// block 0: email=foo%40aaaa
	// block 1: admin&role=user&
	// block 2: uid=42 + padding
	const maliciousAdminEmail = "foo@aaaaadmin"
	maliciousProfile, err := encryptionOracle([]byte(maliciousAdminEmail))
	if err != nil {
		return false, err
	}

	var (
		// We can now compose a cipher text by copy pasting blocks of the two
		// different cipher texts, so that they form an encrypted user profile
		// that decrypts to an admin user.
		b1 = forgedUser[:16]         // email=foo%40bar.
		b2 = forgedUser[16:32]       // aaaaaaacom&role=
		b3 = maliciousProfile[16:32] // admin&role=user&
		b4 = maliciousProfile[32:]   // uid=XX+padding
	)

	// the concatenation of the blocks above gives us:
	// email=foo%40bar.aaaaaaaaaa&role=admin&role=user&uid=XX
	return adminOracle(slices.Concat(b1, b2, b3, b4))
}
