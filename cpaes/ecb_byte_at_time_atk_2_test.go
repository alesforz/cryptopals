package cpaes

import (
	"bytes"
	"testing"

	"github.com/alesforz/cryptopals/cpbytes"
)

func TestByteAtTimeAtk2(t *testing.T) {
	oracle, err := ecbEncryptionOracleWithSecret()
	if err != nil {
		t.Fatal(err)
	}

	decryptedSecret, err := byteAtTimeAtk2(oracle)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("secret length: ", len(decryptedSecret))
	t.Logf("secret: %s \n", decryptedSecret)
}

func TestBytesToChunks(t *testing.T) {
	var (
		data = []byte(
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@",
		)
		wantChunks = [][]byte{
			[]byte("abcdefghijklmnop"),
			[]byte("qrstuvwxyzABCDEF"),
			[]byte("GHIJKLMNOPQRSTUV"),
			[]byte("WXYZ0123456789!@"),
		}
	)

	gotChunks, err := cpbytes.BytesToChunks(data, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotChunks) != len(wantChunks) {
		t.Fatalf("expected %d chunks, got %d", len(wantChunks), len(gotChunks))
	}
	for i, chunk := range gotChunks {
		if !bytes.Equal(chunk, wantChunks[i]) {
			t.Errorf("chunk %d: expected %q, got %q", i, wantChunks[i], chunk)
		}
	}
}

func TestTransposeAndFlattenBlocks(t *testing.T) {
	var (
		blocks = [][][]byte{
			{
				[]byte("abcdefghijklmnop"),
				[]byte("qrstuvwxyzABCDEF"),
				[]byte("GHIJKLMNOPQRSTUV"),
				[]byte("WXYZ0123456789!@"),
			},
			{
				[]byte("ABCDEFGHIJKLMNOP"),
				[]byte("QRSTUVWXYZabcdef"),
				[]byte("ghijklmnopqrstuv"),
				[]byte("wxyz0123456789!@"),
			},
			{
				[]byte("0123456789ABCDEF"),
				[]byte("GHIJKL!@#$%^&*()"),
			},
			{
				[]byte("TheQuickBrownFoxJ"),
				[]byte("umpsOverTheLazyD"),
			},
		}
		wantResult = [][]byte{
			[]byte("abcdefghijklmnop"),
			[]byte("ABCDEFGHIJKLMNOP"),
			[]byte("0123456789ABCDEF"),
			[]byte("TheQuickBrownFoxJ"),
			[]byte("qrstuvwxyzABCDEF"),
			[]byte("QRSTUVWXYZabcdef"),
			[]byte("GHIJKL!@#$%^&*()"),
			[]byte("umpsOverTheLazyD"),
		}
	)
	gotResult := transposeAndFlattenBlocks(blocks)
	if len(gotResult) != len(wantResult) {
		t.Fatalf("expected %d blocks, got %d", len(wantResult), len(gotResult))
	}
	for i, block := range gotResult {
		if !bytes.Equal(block, wantResult[i]) {
			t.Errorf("block %d: expected %q, got %q", i, wantResult[i], block)
		}
	}
}
