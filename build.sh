#!/bin/sh

# Because I'm tired of Makefiles!

build() {
    SRCFILE="$1"
    shift
    go build -o bin/"$SRCFILE" "$SRCFILE".go "$@"
}

build 33_diffie_hellman dh.go random.go
build 34_dh_mitm primitives.go dh.go network.go random.go
build 36_srp primitives.go dh.go network.go random.go
build 38_srp_dictionary_attack primitives.go dh.go network.go random.go
build 39_rsa random.go rsa.go

