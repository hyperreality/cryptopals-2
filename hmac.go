package main

import (
	"crypto/hmac"
)

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)

	return h.Sum(nil)
}
