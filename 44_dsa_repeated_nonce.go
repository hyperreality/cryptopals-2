package main

import (
    "bufio"
    "fmt"
    "math/big"
    "os"
    "strings"
)

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

func main() {
    messages := importMessages("data/44.txt")
    _ = messages
}
