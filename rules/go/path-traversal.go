package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func bad(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: shipguard.go.path-traversal
	data, _ := os.ReadFile(filepath.Join("/srv/data", name))
	_ = data
	// ruleid: shipguard.go.path-traversal
	http.ServeFile(w, r, r.FormValue("path"))
}

func good(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("file"))
	// ok: shipguard.go.path-traversal
	data, _ := os.ReadFile(filepath.Join("/srv/data", name))
	_ = data
	// ok: shipguard.go.path-traversal
	os.ReadFile("/etc/hostname")
}
