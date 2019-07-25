package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
)

var matasano = matasanoParams()

type dsaSignedMsg struct {
	msg string
	s   *big.Int
	r   *big.Int
	m   *big.Int
}

func importMessages(filePath string) []dsaSignedMsg {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var buffer []string
	var messages []dsaSignedMsg

	for scanner.Scan() {
		value := strings.Split(scanner.Text(), ": ")[1]
		buffer = append(buffer, value)

		if len(buffer) == 4 {
			msg := buffer[0]
			s, _ := new(big.Int).SetString(buffer[1], 10)
			r, _ := new(big.Int).SetString(buffer[2], 10)
			m, _ := new(big.Int).SetString(buffer[3], 16)

			message := dsaSignedMsg{msg: msg, s: s, r: r, m: m}
			messages = append(messages, message)

			buffer = nil
		}
	}

	return messages
}

func recoverDsaKeyRepeatedNonce(messages []dsaSignedMsg, publicKey *dsaPublicKey) *dsaPrivateKey {
	privateKey := &dsaPrivateKey{dsaPublicKey: *publicKey}
	_ = privateKey

	seen := make(map[string]int)

	for i, msg := range messages {
		fmt.Println(msg.r)
		if j, ok := seen[msg.r.String()]; ok {
			fmt.Println("found identical r value for:")
			fmt.Println(messages[i].msg)
			fmt.Println(messages[j].msg)

			k := new(big.Int).Sub(messages[i].m, messages[j].m)
			den := new(big.Int).Sub(messages[i].s, messages[j].s)
			k = k.Mul(k, new(big.Int).ModInverse(den, publicKey.q))
			k = k.Mod(k, publicKey.q)

			x := new(big.Int).Mul(messages[i].s, k)
			x = x.Sub(x, dsaHash([]byte(messages[i].msg))).Mod(x, publicKey.q)
			x = x.Mul(x, new(big.Int).ModInverse(messages[i].r, publicKey.q))
			privateKey.x = x.Mod(x, publicKey.q)

			return privateKey
		}

		seen[msg.r.String()] = i
	}

	panic("could not recover privkey")
}

func main() {
	messages := importMessages("data/44.txt")

	y := new(big.Int)
	y.SetString("2d026f4bf30195ede3a088da85e398ef869611d0f68f07"+
		"13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"+
		"5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"+
		"f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"+
		"f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"+
		"2971c3de5084cce04a2e147821", 16)
	chalPublicKey := &dsaPublicKey{dsaParams: matasano, y: y}

	chalPrivKeyHash := "ca8f6f7c66fa362d40760d135b763eb8527d3d52"

	recovered := recoverDsaKeyRepeatedNonce(messages, chalPublicKey)

	hashedX := sha1.Sum([]byte(recovered.x.Text(16)))
	good := hex.EncodeToString(hashedX[:]) == chalPrivKeyHash

	fmt.Println("recovered privkey: " + fmt.Sprint(good))
}
