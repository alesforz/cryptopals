package cpxor

import (
	"bytes"
	"testing"
)

func TestHexStrs(t *testing.T) {
	var (
		hexStr1    = "1c0111001f010100061a024b53535009181c"
		hexStr2    = "686974207468652062756c6c277320657965"
		wantHexStr = "746865206b696420646f6e277420706c6179"
	)

	gotHexStr, err := hexStrs(hexStr1, hexStr2)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if gotHexStr != wantHexStr {
		t.Errorf("got: %s\nwant: %s\n", gotHexStr, wantHexStr)
	}
}

func TestBlocks(t *testing.T) {
	t.Run("EqualLength", func(t *testing.T) {
		var (
			b1 = []byte{0x01, 0x02, 0x03}
			b2 = []byte{0x01, 0x02, 0x03}
		)
		got, err := blocks(b1, b2)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		want := []byte{0x00, 0x00, 0x00}
		if !bytes.Equal(got, want) {
			t.Errorf("got: %v\nwant: %v\n", got, want)
		}
	})

	t.Run("DifferentLength", func(t *testing.T) {
		var (
			b1 = []byte{0x01, 0x02, 0x03}
			b2 = []byte{0x01, 0x02}
		)
		_, err := blocks(b1, b2)
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		want := "input blocks are of different lengths: 3 and 2"
		if err.Error() != want {
			t.Errorf("got: %s\nwant: %s\n", err.Error(), want)
		}
	})
}
