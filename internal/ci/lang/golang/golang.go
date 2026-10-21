// Package golang implements the Go language defaults for `shipguard ci`.
package golang

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/policy"
)

const (
	junitPath    = ".shipguard/ci/junit-go.xml"
	profilePath  = ".shipguard/ci/cover.out"
	coveragePath = ".shipguard/ci/coverage.xml"
	defaultTO    = 30 * time.Minute
)

// Go is the Go language.
type Go struct{}

// Name returns "go".
func (Go) Name() string { return "go" }

// Markers returns the files that identify a Go project.
func (Go) Markers() []string { return []string{"go.mod"} }

// goMod holds the directives shipguard needs from go.mod.
type goMod struct{ module, goVer, toolchain string }

func parseGoMod(path string) (goMod, error) {
	f, err := os.Open(path)
	if err != nil {
		return goMod{}, fmt.Errorf("read go.mod: %w", err)
	}
	defer func() { _ = f.Close() }()
	var m goMod
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "module", "go", "toolchain":
			if len(fields) != 2 {
				return goMod{}, fmt.Errorf("go.mod:%d: malformed %s directive", n, fields[0])
			}
			v := strings.Trim(fields[1], `"`)
			switch fields[0] {
			case "module":
				m.module = v
			case "go":
				m.goVer = v
			default:
				m.toolchain = v
			}
		}
	}
	if err := sc.Err(); err != nil {
		return goMod{}, fmt.Errorf("read go.mod: %w", err)
	}
	return m, nil
}

// Detect reads the Go version from go.mod: the toolchain line, else the go line.
func (Go) Detect(dir string, _ map[string]string) (ci.Detection, error) {
	m, err := parseGoMod(filepath.Join(dir, "go.mod"))
	if err != nil {
		return ci.Detection{}, err
	}
	if v := strings.TrimPrefix(m.toolchain, "go"); strings.HasPrefix(m.toolchain, "go") && v != "" {
		return ci.Detection{Language: "go", Version: v, Source: "go.mod"}, nil
	}
	if m.goVer != "" {
		return ci.Detection{Language: "go", Version: m.goVer, Source: "go.mod"}, nil
	}
	return ci.Detection{Language: "go", Source: "default"}, errors.New("go.mod has no go directive")
}

// Toolchain returns the installed Go version without the "go" prefix.
func (Go) Toolchain(ctx context.Context, run func(ctx context.Context, argv ...string) (string, error)) (string, error) {
	out, err := run(ctx, "go", "env", "GOVERSION")
	if err != nil {
		return "", fmt.Errorf("go env GOVERSION: %w", err)
	}
	return strings.TrimPrefix(strings.TrimSpace(out), "go"), nil
}

// Steps returns install, lint, test and build.
func (Go) Steps(ctx context.Context, env ci.Env, _ ci.Detection, cfg policy.CIConfig) ([]ci.Step, error) {
	to := cfg.Timeouts.PerStep
	if to == 0 {
		to = defaultTO
	}
	steps := []ci.Step{{
		Name:    "install",
		Cmds:    []ci.Cmd{{Argv: []string{"go", "mod", "download"}}},
		Timeout: to,
	}}

	build := func(name ci.StepName, sc policy.CIStep, junit []string, cov string,
		def func() ([]ci.Cmd, error), after func(context.Context, string) error) error {
		s := ci.Step{Name: name, Timeout: to}
		if !sc.On() {
			s.Skip = "disabled in config"
			steps = append(steps, s)
			return nil
		}
		if sc.Run != "" {
			s.Cmds = []ci.Cmd{{Shell: sc.Run}}
		} else {
			s.JUnit, s.Coverage = junit, cov
			cmds, err := def()
			if err != nil {
				return err
			}
			s.Cmds, s.After = cmds, after
		}
		if len(sc.JUnit) > 0 {
			s.JUnit = sc.JUnit
		}
		if sc.Coverage != "" {
			s.Coverage = sc.Coverage
		}
		steps = append(steps, s)
		return nil
	}

	if err := build("lint", cfg.Steps.Lint, nil, "", func() ([]ci.Cmd, error) {
		bin, err := env.Tools(ctx, "golangci-lint")
		if err != nil {
			return nil, fmt.Errorf("golangci-lint: %w", err)
		}
		return []ci.Cmd{{Argv: []string{bin, "run", "./..."}}}, nil
	}, nil); err != nil {
		return nil, err
	}
	if err := build("test", cfg.Steps.Test, []string{junitPath}, coveragePath, func() ([]ci.Cmd, error) {
		bin, err := env.Tools(ctx, "gotestsum")
		if err != nil {
			return nil, fmt.Errorf("gotestsum: %w", err)
		}
		return []ci.Cmd{
			{Argv: []string{"mkdir", "-p", ".shipguard/ci"}},
			{Argv: []string{bin, "--junitfile", junitPath, "--", "-race", "-coverprofile=" + profilePath, "./..."}},
		}, nil
	}, coverAfter); err != nil {
		return nil, err
	}
	if err := build("build", cfg.Steps.Build, nil, "", func() ([]ci.Cmd, error) {
		return []ci.Cmd{{Argv: []string{"go", "build", "./..."}}}, nil
	}, nil); err != nil {
		return nil, err
	}
	return steps, nil
}

// coverAfter converts the Go cover profile to Cobertura. A missing profile is not an error.
func coverAfter(_ context.Context, dir string) error {
	in := filepath.Join(dir, profilePath)
	if _, err := os.Stat(in); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	f, err := os.Create(filepath.Join(dir, coveragePath))
	if err != nil {
		return fmt.Errorf("create coverage.xml: %w", err)
	}
	if err := CoverToCobertura(in, dir, f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
