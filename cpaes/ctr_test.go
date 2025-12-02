package cpaes

import (
	"crypto/aes"
	"encoding/base64"
	"testing"

	"github.com/alesforz/cryptopals/cpbytes"
	"github.com/alesforz/cryptopals/cpxor"
)

// Solves challenge 18 of set 3
func TestDecryptCTR(t *testing.T) {
	var (
		cipherTextBase64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
		key              = []byte("YELLOW SUBMARINE")
		nonce            uint64
	)
	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		t.Fatalf("Failed to decode cipher text from base64: %v", err)
	}

	plainText, err := ctr(cipherText, key, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt CTR: %v", err)
	}
	t.Log("Decrypted plaintext:\n", string(plainText))
}

// Solves challenge 19 of set 3
func TestBreakCTRWithSubs(t *testing.T) {
	var (
		plainTexts = []string{
			"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
			"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
			"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
			"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
			"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
			"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
			"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
			"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
			"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
			"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
			"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
			"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
			"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
			"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
			"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
			"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
			"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
			"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
			"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
			"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
			"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
			"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
			"U2hlIHJvZGUgdG8gaGFycmllcnM/",
			"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
			"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
			"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
			"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
			"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
			"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
			"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
			"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
			"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
			"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
			"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
			"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
			"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
			"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
			"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
			"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
			"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		}
		cipherTexts = make([][]byte, len(plainTexts))
		nonce       uint64
	)
	key, err := cpbytes.Random(uint(aes.BlockSize), uint(aes.BlockSize))
	if err != nil {
		t.Fatalf("generating random encryption key: %s", err)
	}

	for i, ptB64 := range plainTexts {
		pt, err := base64.StdEncoding.DecodeString(ptB64)
		if err != nil {
			t.Fatalf("decoding plain text %d from base64: %v", i, err)
		}

		ct, err := ctr(pt, key, nonce)
		if err != nil {
			t.Fatalf("encrypting with AES CTR plain text %d: %v", i, err)
		}
		cipherTexts[i] = ct
	}

	recoveredKeyStream, err := breakCTRWithFixedNonce(cipherTexts)
	if err != nil {
		t.Fatalf("breaking CTR with fixed nonce: %v", err)
	}

	t.Logf("Recovered key stream: %s", recoveredKeyStream)

	for i, ct := range cipherTexts {
		pt := cpxor.DecryptWithRepeatingKey(ct, recoveredKeyStream)
		t.Logf("Recovered plain text %d: %s", i, string(pt))
	}
}
