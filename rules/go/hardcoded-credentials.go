package main

import "os"

func bad() {
	// ruleid: shipguard.go.hardcoded-credentials
	dbPassword := "changeme-not-a-secret"
	// ruleid: shipguard.go.hardcoded-credentials
	var apiToken = "changeme-not-a-secret"
	_, _ = dbPassword, apiToken
}

func good() {
	// ok: shipguard.go.hardcoded-credentials
	dbPassword := os.Getenv("DB_PASSWORD")
	// ok: shipguard.go.hardcoded-credentials
	passwordLabel := ""
	// ok: shipguard.go.hardcoded-credentials
	tokenURL := "https://auth.example.com/token"
	// ok: shipguard.go.hardcoded-credentials
	passwordPrompt := "Enter your password now"
	// ok: shipguard.go.hardcoded-credentials
	secretName := "db-credentials"
	_, _, _, _, _ = dbPassword, passwordLabel, tokenURL, passwordPrompt, secretName
}
