// Package ci holds the core types shared by `shipguard ci`.
package ci

import (
	"context"
	"time"

	"github.com/faridlamaul/shipguard/internal/policy"
)

// StepName is "install", "lint", "test" or "build".
type StepName string

// Detection is the detected language and toolchain version.
// Source is the file that set Version, or "default" / "config".
type Detection struct{ Language, Version, Source string }

// Cmd is one command. Shell != "" means run `sh -c Shell`.
type Cmd struct {
	Argv  []string
	Shell string
	Env   map[string]string
}

// Step is one pipeline step.
type Step struct {
	Name     StepName
	Cmds     []Cmd
	JUnit    []string // globs relative to the project dir
	Coverage string   // Cobertura path relative to the project dir
	Skip     string   // non-empty: skipped with this reason
	Timeout  time.Duration
	After    func(ctx context.Context, dir string) error // runs after Cmds succeed
}

// Env is what a language needs to build its steps.
type Env struct {
	Dir      string                                                 // project dir (after --dir)
	Tools    func(ctx context.Context, name string) (string, error) // tools.Cache.Ensure by name
	Defaults map[string]string                                      // from tools.Load
}

// Language is implemented by each supported language.
type Language interface {
	Name() string
	Markers() []string
	Detect(dir string, defaults map[string]string) (Detection, error)
	Toolchain(ctx context.Context, run func(ctx context.Context, argv ...string) (string, error)) (string, error)
	Steps(ctx context.Context, env Env, det Detection, cfg policy.CIConfig) ([]Step, error)
}
