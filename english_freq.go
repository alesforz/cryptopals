package main

// taken from
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

const _spaceFrequency = 0.1918182
