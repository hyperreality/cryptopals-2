package main

import (
	"fmt"
	"math/big"
)

func main() {
	privKey0 := generateRsa(1024, 3)
	privKey1 := generateRsa(1024, 3)
	privKey2 := generateRsa(1024, 3)

	pubKey0 := getPublicKey(privKey0)
	pubKey1 := getPublicKey(privKey1)
	pubKey2 := getPublicKey(privKey2)

	msg := "E=3 RSA Broadcast attack"
	cText0 := encryptRsaText(pubKey0, msg)
	cText1 := encryptRsaText(pubKey1, msg)
	cText2 := encryptRsaText(pubKey2, msg)

	m_s_0 := new(big.Int).Mul(pubKey1.n, pubKey2.n)
	m_s_1 := new(big.Int).Mul(pubKey0.n, pubKey2.n)
	m_s_2 := new(big.Int).Mul(pubKey0.n, pubKey1.n)

	x_0 := new(big.Int).ModInverse(m_s_0, pubKey0.n)
	x_1 := new(big.Int).ModInverse(m_s_1, pubKey1.n)
	x_2 := new(big.Int).ModInverse(m_s_2, pubKey2.n)

	part0 := x_0.Mul(x_0, cText0).Mul(x_0, m_s_0)
	part1 := x_1.Mul(x_1, cText1).Mul(x_1, m_s_1)
	part2 := x_2.Mul(x_2, cText2).Mul(x_2, m_s_2)

	N_012 := new(big.Int)
	N_012 = N_012.Mul(pubKey0.n, pubKey1.n).Mul(N_012, pubKey2.n)

	res := new(big.Int)
	res = res.Add(res, part0).Add(res, part1).Add(res, part2).Mod(res, N_012)

	pText := string(cbrt(res).Bytes())

	fmt.Println("plaintext: " + pText)
}
