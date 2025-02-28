package cptext

import "unicode/utf8"

// _spaceFrequency is the frequency of the space character in English text.
// Taken from
// https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
const _spaceFrequency = 0.1918182

// _englishLetterFrequencies is a table of the frequencies of each letter in
// English text.
// Taken from
// https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
var _englishLetterFrequencies = [26]float64{
	// a        b        c         d        e
	0.084966, 0.020720, 0.045388, 0.033844, 0.111607,
	// f        g        h         i        j
	0.018121, 0.024705, 0.030034, 0.075448, 0.001965,
	// k        l        m         n        o
	0.011016, 0.054893, 0.030129, 0.066544, 0.071635,
	// p        q        r         s        t
	0.031671, 0.001962, 0.075809, 0.057351, 0.069509,
	// u        v        w         x        y
	0.036308, 0.010074, 0.012899, 0.002902, 0.017779,
	// z
	0.002722,
}

// ComputeScore calculates and returns a score for the given UTF-8 text based on
// how closely its character frequencies match typical English text. A higher
// score indicates a closer match to valid English.
func ComputeScore(data []byte) float64 {
	const uppercaseToLowercaseShift = 'a' - 'A'
	var (
		// we use [utf8.RuneCountInString] instead of len(text) because
		// len(text) returns the number of *bytes*. However, recall that in
		// UTF-8 some characters are encoded using 2 bytes, therefore len(text)
		// could return a number which is higher than the actual number of
		// characters in the text. In contrast [utf8.RuneCountInString] returns
		// the exact number of *characters* in the text, which is what we want
		// here.
		nChars = float64(utf8.RuneCount(data))
		score  float64
	)

	for _, b := range data {
		if b >= 'A' && b <= 'Z' {
			b += uppercaseToLowercaseShift
		}

		if b >= 'a' && b <= 'z' {
			score += _englishLetterFrequencies[b-'a']
		} else if b == ' ' {
			score += _spaceFrequency
		}
	}

	// Normalization: a longer text will have a higher score because it has more
	// characters. By normalizing, we adjust for the length of the text, making
	// scores from different text lengths comparable.
	// By doing this, the function calculates the average score per character,
	// giving a metric that represents the "English-likeness" of the text on a
	// per-character basis.
	return score / nChars
}
