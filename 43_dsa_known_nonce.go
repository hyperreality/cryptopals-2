package main

import (
	"crypto/sha1"
	"fmt"
	"encoding/hex"
	"math/big"
)

var matasano = matasanoParams()

func dsaTest() {
	privateKey := generateDsaKey(matasano)
	publicKey := privateKey.getDsaPublicKey()
	fmt.Println("x (private): " + privateKey.x.String())
	fmt.Println("y (public):  " + publicKey.y.String())

	msg := "Test message"
	fmt.Println(msg)

	signature := privateKey.sign([]byte(msg))
	verified := publicKey.verify([]byte(msg), signature)

	fmt.Println("verified: " + fmt.Sprint(verified))
}

func recoverDsaKeyWithNonce(msg []byte, publicKey *dsaPublicKey, sig *dsaSignature) *dsaPrivateKey {
    privateKey := &dsaPrivateKey{dsaPublicKey: *publicKey}

    for i := 1; i < 65536; i++ {
		k := big.NewInt(int64(i))

		x := new(big.Int).Mul(sig.s, k)
		x = x.Sub(x, dsaHash(msg)).Mod(x, publicKey.q)
		x = x.Mul(x, new(big.Int).ModInverse(sig.r, publicKey.q))
		privateKey.x = x.Mod(x, publicKey.q)

        signed := privateKey.sign(msg)

		if publicKey.verify(msg, signed) {
			return privateKey
		}
	}

    panic("could not recover privkey")
}

func main() {
    msg := "For those that envy a MC it can be hazardous to your health\n" +
          "So be friendly, a matter of life and death, just like a etch-a-sketch\n"

    y := new(big.Int)
	y.SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"+
		"abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"+
		"e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"+
		"1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"+
		"bb283e6633451e535c45513b2d33c99ea17", 16)
    chalPublicKey := &dsaPublicKey{dsaParams: matasano, y: y}

	r := new(big.Int)
	r.SetString("548099063082341131477253921760299949438196259240", 10)
	s := new(big.Int)
    s.SetString("857042759984254168557880549501802188789837994940", 10)
    chalSig := &dsaSignature{r: r, s: s}

    chalPrivKeyHash := "0954edd5e0afe5542a4adf012611a91912a3ec16"

    recovered := recoverDsaKeyWithNonce([]byte(msg), chalPublicKey, chalSig)

    hashedX := sha1.Sum([]byte(recovered.x.Text(16)))
    good := hex.EncodeToString(hashedX[:]) == chalPrivKeyHash

    fmt.Println("recovered privkey: " + fmt.Sprint(good))
}
