package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"sync"
)

var nist = nistParams()
var N = nist.p
var g = nist.g
var k = new(big.Int).SetInt64(3)

var I = "hyperreality@github.com"
var P = "hunter2"

func Client(net Network) bool {
	exp := makeSecret(nist)
	a, A := exp.a, exp.A

	net.Write(I)
	net.Write(A)

	salt := readBytes(net)
	B := readInt(net)

	uH := sha256.Sum256(append(A.Bytes()[:], B.Bytes()[:]...))
	u := new(big.Int).SetBytes(uH[:])

	xH := sha256.Sum256(append(salt[:], []byte(P)...))
	x := new(big.Int).SetBytes(xH[:])

	S := new(big.Int).Exp(g, x, N)
	S = S.Mul(S, k)
	S = S.Sub(B, S)
	e := new(big.Int).Mul(u, x)
	e = e.Add(a, e)
	S = S.Exp(S, e, N)

	K := sha256.Sum256(S.Bytes())
	hmac := hmacSHA256(K[:], salt)
	net.Write(hmac)

	ok := net.Read().(bool)

	return ok
}

func Server(net Network) bool {
	I := readString(net)
	A := readInt(net)

	_ = I

	salt := randBytes(16)
	xH := sha256.Sum256(append(salt[:], []byte(P)...))
	x := new(big.Int).SetBytes(xH[:])
	v := new(big.Int).Exp(g, x, N)

	exp := makeSecret(nist)
	b, B := exp.a, exp.A.Add(exp.A, new(big.Int).Mul(k, v))

	net.Write(salt)
	net.Write(B)

	uH := sha256.Sum256(append(A.Bytes()[:], B.Bytes()[:]...))
	u := new(big.Int).SetBytes(uH[:])

	S := new(big.Int).Exp(v, u, N)
	S = S.Mul(A, S)
	S = S.Exp(S, b, N)

	K := sha256.Sum256(S.Bytes())
	serverHmac := hmacSHA256(K[:], salt)

	clientHmac := readBytes(net)

	fmt.Println(base64.StdEncoding.EncodeToString(serverHmac))
	fmt.Println(base64.StdEncoding.EncodeToString(clientHmac))

	ok := hmac.Equal(serverHmac, clientHmac)

	net.Write(ok)

	return ok
}

func main() {
	in := make(chan interface{})
	out := make(chan interface{})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		clientNet := &network{in: in, out: out}
		Client(clientNet)
		wg.Done()
	}()

	go func() {
		serverNet := &network{in: out, out: in}
		Server(serverNet)
		wg.Done()
	}()

	wg.Wait()
}
