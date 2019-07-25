package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
)

var keySize int

func brokenVerifier(key *publicKey, msg string, sig *big.Int) bool {
	b := encryptRsa(key, sig).Bytes()

	if b[0] != 0x01 {
		return false
	}

	pos := 1

	for ; b[pos] == 0xff; pos++ {
	}

	if b[pos] != 0x00 {
		return false
	}

	pos++

	l := int(b[pos])
	var h1 [32]byte
	copy(h1[:], b[pos+1:pos+l+1])
	h2 := sha256.Sum256([]byte(msg))

	return h1 == h2
}

func simplePkcs15Pad(bits int, hash []byte) []byte {
	buf := make([]byte, bits/8)
	pos := len(buf) - len(hash) - 1

	buf[1] = 0x01

	for i := 2; i < pos-1; i++ {
		buf[i] = byte(0xff)
	}

	buf[pos] = byte(len(hash))
	copy(buf[pos+1:], hash)

	return buf
}

func rsaSign(key *privateKey, msg string) *big.Int {
	hash := sha256.Sum256([]byte(msg))
	padded := simplePkcs15Pad(1024, hash[:])
	m := new(big.Int).SetBytes(padded)
	return decryptRsa(key, m)
}

func forgeSignature(msg string) *big.Int {
	stuffingSize := int(0.75 * float64(keySize))
	hash := sha256.Sum256([]byte(msg))
	padded := simplePkcs15Pad(keySize-stuffingSize, hash[:])
	stuffing := bytes.Repeat([]byte{0xff}, stuffingSize/8)
	m := append(padded, stuffing...)

	return cbrt(new(big.Int).SetBytes(m))
}

func main() {
	keySize = 4096
	privateKey := generateRsa(keySize, 3)
	publicKey := getPublicKey(privateKey)

	msg := "Test message"

	signature := rsaSign(privateKey, msg)
	good := brokenVerifier(publicKey, msg, signature)

	str := fmt.Sprint(good)
	fmt.Println("Verifier test: " + str)

	signature = forgeSignature(msg)
	good = brokenVerifier(publicKey, msg, signature)

	str = fmt.Sprint(good)
	fmt.Println("Forged test: " + str)
}
