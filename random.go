package main

import (
	"crypto/rand"
	"math/big"
)

func randBytes(size int) []byte {
	b := make([]byte, size)

	if _, err := rand.Read(b); err != nil {
		panic("RNG fail")
	}

	return b
}

func randInt(max *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, max)

	if err != nil {
		panic("RNG fail")
	}

	return n
}

func randPrime(size int) *big.Int {
	p, err := rand.Prime(rand.Reader, size)

	if err != nil {
		panic("RNG fail")
	}

	return p
}
