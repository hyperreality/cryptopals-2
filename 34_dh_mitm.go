package main

import (
	"crypto/sha256"
	"math/big"
	"sync"
)

var nist = nistParams()
var p = nist.p
var g = nist.g

func generateKey(s *big.Int) []byte {
	hash := sha256.Sum256(s.Bytes())
	return hash[0:16]
}

func Alice(msg []byte, net Network) {
	exp := makeSecret(nist)
	a, A := exp.a, exp.A

	net.Write(p)
	net.Write(g)
	net.Write(A)

	B := readInt(net)

	s := new(big.Int)
	s.Exp(B, a, p)

	key := generateKey(s)
	ciphertext := SimpleCBCEncrypt(msg, key)

	net.Write(ciphertext)
	net.Read()
}

func Bob(net Network) {
	p := readInt(net)
	g := readInt(net)
	A := readInt(net)

	exp := makeSecret(dhParams{p: p, g: g})
	b, B := exp.a, exp.A

	net.Write(B)

	s := new(big.Int)
	s.Exp(A, b, p)

	key := generateKey(s)
	msg := SimpleCBCDecrypt(readBytes(net), key)
	ciphertext := SimpleCBCEncrypt(msg, key)

	net.Write(ciphertext)
}

func Eve(alice Network, bob Network) ([]byte, []byte) {
	p := readInt(alice)
	g := readInt(alice)
	A := readInt(alice)

	bob.Write(p)
	bob.Write(g)
	_ = A
	bob.Write(p)

	B := readInt(bob)
	_ = B
	alice.Write(p)

	aliceCiphertext := readBytes(alice)
	bob.Write(aliceCiphertext)

	bobCiphertext := readBytes(bob)
	alice.Write(bobCiphertext)

	s := new(big.Int) // B^a % p is p^a % p so s is 0
	key := generateKey(s)

	aliceMsg := SimpleCBCDecrypt(aliceCiphertext, key)
	bobMsg := SimpleCBCDecrypt(bobCiphertext, key)

	return aliceMsg, bobMsg
}

func main() {
	aliceIn := make(chan interface{})
	aliceOut := make(chan interface{})

	bobIn := make(chan interface{})
	bobOut := make(chan interface{})

	var wg sync.WaitGroup
	wg.Add(3)

	msg := "helloworld123456"
	var aliceMsg, bobMsg []byte

	go func() {
		aliceNet := &network{in: aliceIn, out: aliceOut}
		Alice([]byte(msg), aliceNet)
		wg.Done()
	}()

	go func() {
		bobNet := &network{in: bobIn, out: bobOut}
		Bob(bobNet)
		wg.Done()
	}()

	go func() {
		aliceNet := &network{in: aliceOut, out: aliceIn}
		bobNet := &network{in: bobOut, out: bobIn}
		aliceMsg, bobMsg = Eve(aliceNet, bobNet)
		wg.Done()
	}()

	wg.Wait()

	println("Original message: " + msg)
	println("Intercepted from Alice: " + string(aliceMsg))
	println("Intercepted from Bob: " + string(bobMsg))
}
