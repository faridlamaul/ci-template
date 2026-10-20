package main

import "net/http"

func bad(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: shipguard.go.ssrf
	http.Get(target)
	// ruleid: shipguard.go.ssrf
	http.NewRequest("GET", r.FormValue("u"), nil)
}

func good() {
	// ok: shipguard.go.ssrf
	http.Get("https://api.example.com/health")
}

func badClient(c *http.Client, r *http.Request) {
	// ruleid: shipguard.go.ssrf
	c.Get(r.FormValue("target"))
}
