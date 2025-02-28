package cphex

import "testing"

func TestToBase64(t *testing.T) {
	const (
		hexStr        = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		wantBase64Str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	gotBase64Str, err := ToBase64(hexStr)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if gotBase64Str != wantBase64Str {
		t.Errorf("got: %s\nwant: %s\n", gotBase64Str, wantBase64Str)
	}
}
