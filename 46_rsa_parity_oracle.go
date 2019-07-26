package main

import (
	"encoding/base64"
	"fmt"
	"math/big"
)

var privKey = generateRsa(1024, 3)

func parityOracle(encrypted *big.Int) bool {
	decrypted := decryptRsa(privKey, encrypted)

	fmt.Println(decrypted.String())
	isEven := new(big.Int).Mod(decrypted, big.NewInt(2)).Sign() == 0

	return isEven
}

func attackParityOracle(publicKey *publicKey, encrypted *big.Int) string {
	lowerBound := big.NewInt(0)
	upperBound := new(big.Int).Set(publicKey.n)

	current := new(big.Int).Set(encrypted)
	multiplier := encryptRsa(publicKey, big.NewInt(2))

	for lowerBound.Cmp(upperBound) != 0 {
		current = current.Mul(current, multiplier).Mod(current, publicKey.n)

		mid := new(big.Int).Add(lowerBound, upperBound)
		mid = mid.Div(mid, big.NewInt(2))

		if parityOracle(current) {
			upperBound = mid
		} else {
			lowerBound = mid
		}
	}

	// Bad last byte due to division truncation
	for i := 0; i < 256; i++ {
		b := upperBound.Bytes()
		b[len(b)-1] = byte(i)
		upperBound.SetBytes(b)

		if encryptRsa(publicKey, upperBound).Cmp(encrypted) == 0 {
			return string(upperBound.Bytes())
		}
	}

	panic("Failed to decrypt")
}

func main() {
	publicKey := getPublicKey(privKey)

	chalString64 := "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	chalString, _ := base64.StdEncoding.DecodeString(chalString64)

	encrypted := encryptRsaText(publicKey, string(chalString))

	decrypted := attackParityOracle(publicKey, encrypted)
	fmt.Println(decrypted)
}
