package main

import "testing"

func TestHexToBase64(t *testing.T) {
	var (
		hexTestStr    = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		base64WantStr = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	gotStr, err := HexToBase64(hexTestStr)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if gotStr != base64WantStr {
		t.Errorf("got: %s\nwant: %s\n", gotStr, base64WantStr)
	}
}

func TestXORHexStrings(t *testing.T) {
	var (
		hexStr1    = "1c0111001f010100061a024b53535009181c"
		hexStr2    = "686974207468652062756c6c277320657965"
		hexWantStr = "746865206b696420646f6e277420706c6179"
	)

	gotStr, err := XORHexStrings(hexStr1, hexStr2)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if gotStr != hexWantStr {
		t.Errorf("got: %s\nwant: %s\n", gotStr, hexWantStr)
	}
}
