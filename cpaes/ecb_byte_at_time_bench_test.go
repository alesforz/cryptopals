package cpaes

import "testing"

// NOTE: remember to comment out the println statements in the functions before
// running the benchmark.
func BenchmarkByteAtTime(b *testing.B) {
	oracle, err := ecbEncryptionOracleWithSecret()
	if err != nil {
		b.Fatal(err)
	}

	b.Run("byteAtTimeAtk", func(b *testing.B) {
		for b.Loop() {
			_, err := byteAtTimeAtk(oracle)
			if err != nil {
				b.Error(err)
			}
		}
	})

	b.Run("byteAtTimeAtk2", func(b *testing.B) {
		for b.Loop() {
			_, err := byteAtTimeAtk2(oracle)
			if err != nil {
				b.Error(err)
			}
		}
	})

}
