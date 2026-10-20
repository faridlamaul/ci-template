package main

import "unsafe"

func bad(f *float64) uint64 {
	// ruleid: shipguard.go.unsafe-usage
	return *(*uint64)(unsafe.Pointer(f))
}

func good(f *float64) float64 {
	// ok: shipguard.go.unsafe-usage
	return *f
}
