package main

import (
	"crypto/sha1"
	"math/big"
)

type dsaParams struct {
	q *big.Int
	p *big.Int
	g *big.Int
}

type dsaPublicKey struct {
	dsaParams
	y *big.Int
}

type dsaPrivateKey struct {
	dsaPublicKey
	x *big.Int
}

type dsaSignature struct {
	r *big.Int
	s *big.Int
}

func matasanoParams() dsaParams {
	var q = new(big.Int)
	var p = new(big.Int)
	var g = new(big.Int)

	q.SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
	p.SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7"+
		"859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"+
		"2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"+
		"ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"+
		"b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"+
		"1a584471bb1", 16)
	g.SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"+
		"458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"+
		"322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"+
		"0f5b64c36b625a097f1651fe775323556fe00b3608c887892"+
		"878480e99041be601a62166ca6894bdd41a7054ec89f756ba"+
"9fc95302291", 16)

	return dsaParams{p: p, q: q, g: g}
}

func positiveIntLessThan(upperBound *big.Int) *big.Int {
	x := new(big.Int)

	for {
        x.SetBytes(randBytes(upperBound.BitLen() / 8))

        if x.Sign() != 0 && x.Cmp(upperBound) < 0 {
            return x
        }
	}
}

func generateDsaKey(params dsaParams) *dsaPrivateKey {
    x := positiveIntLessThan(params.q)
    y := new(big.Int).Exp(params.g, x, params.p)

    publicKey := dsaPublicKey{dsaParams: params, y: y}

    return &dsaPrivateKey{dsaPublicKey: publicKey, x: x}
}

func (key *dsaPrivateKey) getDsaPublicKey() *dsaPublicKey {
	return &key.dsaPublicKey
}

func dsaHash(msg []byte) *big.Int {
    hash := sha1.Sum([]byte(msg))
    return new(big.Int).SetBytes(hash[:])
}

func (key *dsaPrivateKey) sign(data []byte) *dsaSignature {
	for {
        k := positiveIntLessThan(key.q)

		r := new(big.Int).Exp(key.g, k, key.p)
        r = r.Mod(r, key.q)
		if r.Sign() == 0 {
			continue
		}

		s := dsaHash(data)
		s = s.Add(s, new(big.Int).Mul(key.x, r))
		s = s.Mul(k.ModInverse(k, key.q), s).Mod(s, key.q)
		if s.Sign() == 0 {
			continue
		}

		return &dsaSignature{r: r, s: s}
	}
}

func (key *dsaPublicKey) verify(data []byte, sig *dsaSignature) bool {

	if sig.r.Sign() == 0 || sig.r.Cmp(key.q) >= 0 || sig.s.Sign() == 0 || sig.s.Cmp(key.q) >= 0 {
		return false
	}

	w := new(big.Int).ModInverse(sig.s, key.q)

	u1 := new(big.Int).Mul(dsaHash(data), w)
	u1 = u1.Mod(u1, key.q)

	u2 := new(big.Int).Mul(sig.r, w)
	u2 = u2.Mod(u2, key.q)

	v1 := new(big.Int).Exp(key.g, u1, key.p)
	v2 := new(big.Int).Exp(key.y, u2, key.p)

	v := new(big.Int).Mul(v1, v2)
	v = v.Mod(v, key.p).Mod(v, key.q)

	return v.Cmp(sig.r) == 0
}
