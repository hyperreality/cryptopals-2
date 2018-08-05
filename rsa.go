package main

import (
	"math/big"
)

type publicKey struct {
	n *big.Int
	e *big.Int
}

type privateKey struct {
	n *big.Int
	e *big.Int
	d *big.Int
}

func generateRsa(bits int, exp int64) *privateKey {
	e := big.NewInt(exp)

	p := new(big.Int)
	q := new(big.Int)
	lambda := new(big.Int)

	for {
		p = randPrime(bits / 2)
		q = randPrime(bits / 2)

		p1 := new(big.Int).Sub(p, big.NewInt(1))
		q1 := new(big.Int).Sub(q, big.NewInt(1))

		lambda = new(big.Int).Mul(p1, q1)

		// ensure gcd(e, λ(n)) = 1; i.e., e and λ(n) are coprime.
		checkGcd := new(big.Int).GCD(nil, nil, e, lambda)
		isCoprime := checkGcd.Int64() == 1

		// ensure |p-q| >= 2^(keysize/2 - 100)
		p_q := new(big.Int).Abs(new(big.Int).Sub(p, q))
		bitshift := bits/2 - 100
		checkp_q := new(big.Int).Rsh(p_q, uint(bitshift))
		isDistance := checkp_q.Int64() != 0

		if isCoprime && isDistance {
			break
		}
	}

	n := new(big.Int).Mul(p, q)
	d := new(big.Int).ModInverse(e, lambda)

	return &privateKey{n: n, e: e, d: d}
}

func getPublicKey(key *privateKey) *publicKey {
	return &publicKey{n: key.n, e: key.e}
}

func encryptRsa(key *publicKey, msg *big.Int) *big.Int {
	return new(big.Int).Exp(msg, key.e, key.n)
}

func decryptRsa(key *privateKey, c *big.Int) *big.Int {
	return new(big.Int).Exp(c, key.d, key.n)
}

func encryptRsaText(key *publicKey, msg string) *big.Int {
	m := new(big.Int).SetBytes([]byte(msg))

	return encryptRsa(key, m)
}

func decryptRsaText(key *privateKey, c *big.Int) string {
	decrypted := decryptRsa(key, c)

	return string(decrypted.Bytes())
}
