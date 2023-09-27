package main

import (
	"math"
	"testing"
)

// Check whether the letter frequencies sum up to 1.
func TestEnglishLetterFrequencies(t *testing.T) {
	var sum float64
	for _, freq := range _englishLetterFrequencies {
		sum += freq
	}

	const epsilon = 1e-5

	diff := math.Abs(1 - sum)
	if diff > epsilon {
		t.Errorf("frequencies do not sum to 1. Got %.5f", diff)
	}

}
