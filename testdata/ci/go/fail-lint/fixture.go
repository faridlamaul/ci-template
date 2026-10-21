// Package fixture is a minimal project for the shipguard ci end-to-end tests.
package fixture

// Add returns the sum of a and b.
func Add(a, b int) int { return a + b }

// unused is never called, so the unused linter reports it.
func unused() int { return 1 }
