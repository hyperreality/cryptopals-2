package main

import (
	"fmt"
	"math/big"
)

var matasano = matasanoParams()

func main() {
	msg := "Hello world"
	msg2 := "Goodbye world"

	matasano.g = new(big.Int).Add(matasano.p, big.NewInt(1))

	privateKey := generateDsaKey(matasano)
	publicKey := privateKey.getDsaPublicKey()

	signature := privateKey.sign([]byte(msg))
	fmt.Println("r: " + signature.r.String())
	fmt.Println("s: " + signature.s.String())

	good := publicKey.verify([]byte(msg2), signature)

	fmt.Println("falsely verified: " + fmt.Sprint(good))
}
