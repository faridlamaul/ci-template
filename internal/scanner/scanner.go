// Package scanner defines the scanner interface and the scanner implementations.
package scanner

import (
	"context"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// Target describes what a scanner should scan and where it may write.
type Target struct {
	Dir      string // repo root (or base worktree)
	RawDir   string // where raw output is written
	CacheDir string
	Exclude  []string
	Timeout  time.Duration

	// secrets
	LogOpts     string // e.g. "<base>..<head>" for PR; empty = directory scan
	FullHistory bool   // schedule: scan all of git history

	// sast
	Rules, DisableRules []string

	// sca
	DenyLicenses []string
}

// Scanner runs one external tool and returns normalized findings.
type Scanner interface {
	Name() string
	Category() finding.Category
	Scan(ctx context.Context, t Target) ([]finding.Finding, error)
}

// withTimeout applies the target timeout to ctx when it is positive.
func withTimeout(ctx context.Context, t Target) (context.Context, context.CancelFunc) {
	if t.Timeout > 0 {
		return context.WithTimeout(ctx, t.Timeout)
	}
	return ctx, func() {}
}
