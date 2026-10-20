// Package main is an intentionally insecure shipguard test fixture.
package main

import "crypto/tls"

func config() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

func main() { _ = config() }
