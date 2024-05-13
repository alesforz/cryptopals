package main

import "testing"

func TestHexToBase64(t *testing.T) {
	var (
		hexTestStr    = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		base64WantStr = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	gotStr, err := hexToBase64(hexTestStr)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if gotStr != base64WantStr {
		t.Errorf("got: %s\nwant: %s\n", gotStr, base64WantStr)
	}
}
