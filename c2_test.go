package main

import "testing"

func TestXORHexStrings(t *testing.T) {
	var (
		hexStr1    = "1c0111001f010100061a024b53535009181c"
		hexStr2    = "686974207468652062756c6c277320657965"
		hexWantStr = "746865206b696420646f6e277420706c6179"
	)

	gotStr, err := xorHexStrings(hexStr1, hexStr2)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	} else if gotStr != hexWantStr {
		t.Errorf("got: %s\nwant: %s\n", gotStr, hexWantStr)
	}
}
