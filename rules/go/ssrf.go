package main

import (
	"net/http"
	"strings"
)

func bad(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: shipguard.go.ssrf
	http.Get(target)
	// ruleid: shipguard.go.ssrf
	http.NewRequest("GET", r.FormValue("u"), nil)
}

func badClient(c *http.Client, r *http.Request) {
	// ruleid: shipguard.go.ssrf
	c.Get(r.FormValue("target"))
}

func good(r *http.Request) {
	// ok: shipguard.go.ssrf
	http.Get("https://api.example.com/health")
	// ok: shipguard.go.ssrf
	http.NewRequest("POST", "https://api.example.com/x", strings.NewReader(r.FormValue("x")))
	// ok: shipguard.go.ssrf
	http.Post("https://api.example.com/x", "text/plain", strings.NewReader(r.FormValue("x")))
}
