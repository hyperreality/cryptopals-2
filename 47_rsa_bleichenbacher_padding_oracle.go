package main

import (
	"fmt"
	"math/big"
)

var privKey = generateRsa(256, 3)

func pkcs15Oracle(encrypted *big.Int) bool {
	decrypted := decryptRsa(privKey, encrypted)
    b := decrypted.Bytes()

	fmt.Println(decrypted.String())

    if b[0] == 0x00 && b[1] == 0x02 {
        return true
    }

	return false
}

func attackPkcs15Oracle(publicKey *publicKey, encrypted *big.Int) string {
    return ""
}

func main() {
	publicKey := getPublicKey(privKey)

	chalString := "kick it, CC"
    padded := simplePkcs15Pad(256, 0x02, []byte(chalString))
	encrypted := encryptRsa(publicKey, new(big.Int).SetBytes(padded))

	decrypted := attackPkcs15Oracle(publicKey, encrypted)
	fmt.Println(decrypted)
}
