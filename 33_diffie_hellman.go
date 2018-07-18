package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

func main() {
	s := new(big.Int)
	nist := nistParams()

	exp := makeSecret(nist)
	a, A := exp.a, exp.A
	fmt.Println("A: " + A.String())

	exp = makeSecret(nist)
	b, B := exp.a, exp.A
	fmt.Println("B: " + B.String())

	s.Exp(B, a, nist.p)
	digest := fmt.Sprintf("%x", sha256.Sum256(s.Bytes()))
	s.Exp(A, b, nist.p)
	if digest != fmt.Sprintf("%x", sha256.Sum256(s.Bytes())) {
		panic("key digests not equal")
	}

	fmt.Println("Digest: " + digest)
}
