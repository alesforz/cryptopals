package cpbytes

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// AddNoise prepends and appends random bytes to the given data.
// The exact amount of bytes to prepend and append is chosen randomly between min
// and max.
// It does not modify the input slice.
func AddNoise(data []byte, min, max uint) ([]byte, error) {
	if min > max {
		return nil, fmt.Errorf("min is greater than max: %d > %d", min, max)
	}

	prefix, err := Random(min, max)
	if err != nil {
		return nil, fmt.Errorf("generating prefix: %v", err)
	}

	suffix, err := Random(min, max)
	if err != nil {
		return nil, fmt.Errorf("generating suffix: %v", err)
	}

	var (
		pLen, sLen = len(prefix), len(suffix)
		dLen       = len(data)
		buf        = make([]byte, pLen+dLen+sLen)
	)
	copy(buf, prefix)
	copy(buf[pLen:], data)
	copy(buf[pLen+dLen:], suffix)

	return buf, nil
}

// Random returns a slice filled with random bytes.
// The slice's length is chosen securely at random between min and max, inclusive.
func Random(min, max uint) ([]byte, error) {
	if min > max {
		return nil, fmt.Errorf("min is greater than max: %d > %d", min, max)
	}

	// Calculate the range (max - min + 1) as a big.Int to avoid overflow issues.
	rangeMax := new(big.Int).SetUint64(uint64(max - min + 1))

	// Generate a secure random number in [0, rangeMax-1].
	nBig, err := rand.Int(rand.Reader, rangeMax)
	if err != nil {
		return nil, fmt.Errorf("generating random slice length: %v", err)
	}

	var (
		// Make the random length fit in the desired [min, max] range.
		n   = min + uint(nBig.Uint64())
		buf = make([]byte, n)
	)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("filling buffer with random bytes: %v", err)
	}

	return buf, nil
}
