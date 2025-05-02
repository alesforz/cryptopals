package cppad

import (
	"bytes"
	"testing"
)

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
	t.Run("EmptySlice", func(t *testing.T) {
		if !(len(RemovePKCS7([]byte{})) == 0) {
			t.Errorf("expected empty slice")
		}
	})

	var (
		data = []byte{
			'Y', 'E', 'L', 'L', 'O', 'W', 'S', 'U', 'N',
			0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
		}
		pad = byte(7)
	)

	t.Run("Success", func(t *testing.T) {
		want := data[:9]
		got := RemovePKCS7(data)
		if !bytes.Equal(got, want) {
			t.Errorf("\nwant: %q\ngot: %q\n", want, got)
		}
	})

	assertPanic := func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected code to panic")
			}
		}()
		RemovePKCS7(data)
	}

	t.Run("LastByteZero", func(t *testing.T) {
		data[len(data)-1] = 0
		assertPanic(t, data)

		// restore the last byte for the next test
		data[len(data)-1] = pad
	})

	t.Run("LastByteGreaterThanLength", func(t *testing.T) {
		data[len(data)-1] = 8
		assertPanic(t, data)

		// restore the last byte for the next test
		data[len(data)-1] = pad
	})

	t.Run("PaddingBytesNotEqual", func(t *testing.T) {
		data[len(data)-2] = 0x04
		assertPanic(t, data)
	})
}
