package main

import "math/big"

// Simulates a reliable bidirectional network stream
// Source: https://github.com/Metalnem/cryptopals-go/blob/master/network.go

type Network interface {
	Read() interface{}
	Write(interface{})
}

type network struct {
	in  <-chan interface{}
	out chan<- interface{}
}

func (net *network) Read() interface{} {
	return <-net.in
}

func (net *network) Write(x interface{}) {
	net.out <- x
}

func readInt(net Network) *big.Int {
	return net.Read().(*big.Int)
}

func readString(net Network) string {
	return net.Read().(string)
}

func readBytes(net Network) []byte {
	return net.Read().([]byte)
}
