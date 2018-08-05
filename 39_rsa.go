package main

import (
	"fmt"
)

func main() {
	privateKey := generateRsa(1024, 65537)
	fmt.Println("n: " + privateKey.n.String())
	fmt.Println("e: " + privateKey.e.String())
	fmt.Println("d: " + privateKey.d.String())

	publicKey := getPublicKey(privateKey)

	msg := "Test message"

	ciphertext := encryptRsaText(publicKey, msg)
	fmt.Println("ciphertext: " + ciphertext.String())
	plaintext := decryptRsaText(privateKey, ciphertext)
	fmt.Println("plaintext: " + plaintext)
}
