package cpaes

import "testing"

func TestCbcPaddingOracleAtk(t *testing.T) {
	if err := cbcPaddingOracleAtk(); err != nil {
		t.Fatalf("attack failed: %s", err)
	}
}
