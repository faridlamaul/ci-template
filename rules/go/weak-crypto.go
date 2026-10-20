package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
)

func bad(data, key []byte) {
	// ruleid: shipguard.go.weak-crypto
	md5.Sum(data)
	// ruleid: shipguard.go.weak-crypto
	sha1.New()
	// ruleid: shipguard.go.weak-crypto
	rc4.NewCipher(key)
	// ruleid: shipguard.go.weak-crypto
	des.NewCipher(key)
	// ruleid: shipguard.go.weak-crypto
	des.NewTripleDESCipher(key)
}

func good(data []byte) {
	// ok: shipguard.go.weak-crypto
	sha256.Sum256(data)
}
