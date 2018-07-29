package main

import (
	"crypto/aes"
	"crypto/cipher"
    "crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

func SimpleCBCEncrypt(msg, key []byte) []byte {
	ciphertext := make([]byte, aes.BlockSize+len(msg))

	iv := ciphertext[0:aes.BlockSize]
	rand.Read(iv)

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msg)

	return ciphertext
}

func SimpleCBCDecrypt(ciphertext, key []byte) []byte {
	iv := ciphertext[0:aes.BlockSize]
	msg := make([]byte, len(ciphertext)-len(iv))

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(msg, ciphertext[aes.BlockSize:])

	return msg
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)

	return h.Sum(nil)
}

