package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

var serverPrivKey *privateKey
var serverPubKey *publicKey

var seenHashes map[[32]byte]bool

func decryptionServer(blob *big.Int) *big.Int {
	if seenHashes == nil {
		seenHashes = make(map[[32]byte]bool)
	}

	hsh := sha256.Sum256(blob.Bytes()[:])
	if _, seen := seenHashes[hsh]; seen {
		return nil
	}
	seenHashes[hsh] = true

	decrypted := decryptRsa(serverPrivKey, blob)
	return decrypted
}

func main() {
	serverPrivKey = generateRsa(1024, 65537)

	serverPubKey = getPublicKey(serverPrivKey)

	msg := "Test message"
	capturedCiphertext := encryptRsaText(serverPubKey, msg)
	decrypted := decryptionServer(capturedCiphertext)
	fmt.Println("plaintext: " + string(decrypted.Bytes()))

	decrypted = decryptionServer(capturedCiphertext)
	if decrypted != nil {
		panic("Should not be able to decrypt ciphertext again!")
	}

	S := randInt(serverPubKey.n)
	Sx := new(big.Int).Exp(S, serverPubKey.e, serverPubKey.n)
	Cx := Sx.Mul(Sx, capturedCiphertext).Mod(Sx, serverPubKey.n)

	decrypted = decryptionServer(Cx)

	Px := new(big.Int).ModInverse(S, serverPubKey.n)
	Px = Px.Mul(decrypted, Px).Mod(Px, serverPubKey.n)

	fmt.Println("recovered: " + string(Px.Bytes()))
}
