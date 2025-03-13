package cppad

import "testing"

func TestPKCS7(t *testing.T) {
	const data = "YELLOW SUBMARINE"

	// pad "YELLOW SUBMARINE" (16 bytes) to 20 bytes
	got := PKCS7([]byte(data), 20)

	const want = "YELLOW SUBMARINE\x04\x04\x04\x04"
	gotStr := string(got)
	if gotStr != want {
		t.Errorf("want: %q\ngot: %q\n", data, gotStr)
	}
}

func TestRemovePKCS7(t *testing.T) {
	const data = "YELLOW SUBMARINE"

	// pad "YELLOW SUBMARINE" (16 bytes) to 20 bytes
	padded := PKCS7([]byte(data), 20)

	got := RemovePKCS7(padded)

	gotStr := string(got)
	if gotStr != data {
		t.Errorf("want: %q\ngot: %q\n", data, gotStr)
	}
}
