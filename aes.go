package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func SimpleCBCEncrypt(message, key []byte) []byte {
	ciphertext := make([]byte, aes.BlockSize+len(message))

	iv := ciphertext[0:aes.BlockSize]
	rand.Read(iv)

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], message)

	return ciphertext
}

func SimpleCBCDecrypt(ciphertext, key []byte) []byte {
	iv := ciphertext[0:aes.BlockSize]
	message := make([]byte, len(ciphertext)-len(iv))

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(message, ciphertext[aes.BlockSize:])

	return message
}
