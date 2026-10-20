package main

import "crypto/tls"

func bad() *tls.Config {
	// ruleid: shipguard.go.tls-verify-disabled
	return &tls.Config{InsecureSkipVerify: true}
}

func good() *tls.Config {
	// ok: shipguard.go.tls-verify-disabled
	return &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12}
}
