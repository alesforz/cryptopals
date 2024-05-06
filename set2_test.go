package main

import "testing"

func TestPadPKCS7(t *testing.T) {
	data := []byte("YELLOW SUBMARINE")

	// pad "YELLOW SUBMARINE" (16 bytes) to 20 bytes
	padded := padPKCS7(data, 20)

	const want = "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(padded) != want {
		t.Errorf("\nwant:\t%q\ngot:\t%q\n", want, string(padded))
	}
}
