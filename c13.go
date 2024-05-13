package main

import (
	"crypto/aes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// profileFor returns the encoding of a user formatted as a URL query.
// e.g., given email "foo@bar.com", it returns
// "email=foo@bar.com&uid=10&role=user"
func profileFor(email string) (string, error) {
	if strings.ContainsAny(email, "&=") {
		const errMsg = "invalid email address; can't contain '&' or '=' characters"
		return "", errors.New(errMsg)
	}

	// must create it manually instead of using url.Values.Encode because that
	// function percent-encodes special characters (i.e., it encodes '@' to
	// '%40')
	return "email=" + email + "&uid=42&role=user", nil
}

// parseUser parses a user account in the form
// "email=foo@bar.com&uid=10&role=user" and returns it JSON representation as
// {"email":["foo@bar.com"], "uid":["10"], "role":["user"]}.
func parseUser(user string) (string, error) {
	v, err := url.ParseQuery(user)
	if err != nil {
		return "", fmt.Errorf("parsing user %s: %s", user, err)
	}

	js, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("parsing user %s: %s", user, err)
	}

	return string(js), nil
}

func createAdminProfile(
	encryptionOracle, decryptionOracle aesOracle,
) (string, error) {

	cipherText, err := encryptionOracle([]byte("foo@barrr.com"))
	if err != nil {
		return "", fmt.Errorf("encrypting user profile %q: %s", forgedUser, err)
	}

	adminCipherText, err := encryptionOracle([]byte("admin"))
	if err != nil {
		const formatStr = "encrypting 'admin' string %q: %s"
		return "", fmt.Errorf(formatStr, forgedUser, err)
	}

	copy(cipherText[len(cipherText)-aes.BlockSize:], adminCipherText)

	adminUser, err := decryptionOracle(cipherText)
	if err != nil {
		return "", fmt.Errorf("decrypting user profile: %s", err)
	}

	adminUserStr, err := parseUser(string(delPadPkcs7(adminUser)))
	if err != nil {
		return "", err
	}

	return adminUserStr, nil
}
