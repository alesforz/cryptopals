package cppad

import "testing"

func TestPKCS7(t *testing.T) {
	const data = "YELLOW SUBMARINE"

	// pad "YELLOW SUBMARINE" (16 bytes) to 20 bytes
	padded := PKCS7([]byte(data), 20)

	const want = "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(padded) != want {
		t.Errorf("\nwant:\t%q\ngot:\t%q\n", want, string(padded))
	}
}
