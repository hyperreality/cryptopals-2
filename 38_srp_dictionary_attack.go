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
	u := readInt(net)

	xH := sha256.Sum256(append(salt[:], []byte(P)...))
	x := new(big.Int).SetBytes(xH[:])

	S := new(big.Int).Mul(u, x)
	S = S.Add(a, S)
	S = S.Exp(B, S, N)

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
	b, B := exp.a, exp.A

	uB := randBytes(16)
	u := new(big.Int).SetBytes(uB)

	net.Write(salt)
	net.Write(B)
	net.Write(u)

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

func Mallory(net Network) string {
	I := readString(net)
	A := readInt(net)

	_ = I

	// Setting salt to 0, x becomes just the password
	// Set u = 1 to eliminate it
	// Set B = g so that we can use A to cancel a
	// Thus:
	// Client calculation: S = B**(a + ux) % n
	//                       = g**(a + x) % n
	// Server calculation: S = A * g**x % n
	//                       = g**A * g**x % n
	//                       = g**(a + x) % n

	salt := big.NewInt(0).Bytes()
	B := g
	u := big.NewInt(1)

	net.Write(salt)
	net.Write(B)
	net.Write(u)

	clientHmac := readBytes(net)

	net.Write(false) // begin offline attack

	passwords := []string{"1234", "password", "hunter2", "letmein"}

	for _, password := range passwords {
		xH := sha256.Sum256(append(salt[:], []byte(password)...))
		x := new(big.Int).SetBytes(xH[:])

		S := new(big.Int).Exp(g, x, N)
		S = S.Mul(A, S)
		S = S.Mod(S, N)

		K := sha256.Sum256(S.Bytes())

		if hmac.Equal(clientHmac, hmacSHA256(K[:], salt)) {
			return password
		}
	}

	return ""
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

	// go func() {
	//     serverNet := &network{in: out, out: in}
	//     Server(serverNet)
	//     wg.Done()
	// }()

	go func() {
		serverNet := &network{in: out, out: in}
		fmt.Println(Mallory(serverNet))
		wg.Done()
	}()

	wg.Wait()
}
