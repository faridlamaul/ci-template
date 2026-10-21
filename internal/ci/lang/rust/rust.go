// Package rust implements the Rust language defaults for `shipguard ci`.
package rust

import (
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

const defaultTO = 30 * time.Minute

// nextestConfig is the generated nextest tool config: a `ci` profile that writes JUnit.
const nextestConfig = "[profile.ci]\nfail-fast = false\n\n[profile.ci.junit]\npath = \"junit.xml\"\n"

const nextestConfigPath = ".shipguard/ci/nextest.toml"

// Rust is the Rust language.
type Rust struct{}

// Name returns "rust".
func (Rust) Name() string { return "rust" }

// Markers returns the files that identify a Rust project.
func (Rust) Markers() []string { return []string{"Cargo.toml"} }

func readIfExists(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	return string(b), nil
}

// stripComment removes a trailing "# ..." comment that is outside quotes.
func stripComment(l string) string {
	var q byte
	for i := 0; i < len(l); i++ {
		switch c := l[i]; {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#':
			return l[:i]
		}
	}
	return l
}

// tomlChannel returns channel from the [toolchain] table, or "".
func tomlChannel(s string) string {
	in := false
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(stripComment(l))
		if strings.HasPrefix(l, "[") {
			in = l == "[toolchain]"
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !in || !ok || strings.TrimSpace(k) != "channel" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			return v[1 : len(v)-1]
		}
	}
	return ""
}

// Detect reads the toolchain from rust-toolchain.toml, rust-toolchain, or the default.
func (Rust) Detect(dir string, defaults map[string]string) (ci.Detection, error) {
	t, err := readIfExists(filepath.Join(dir, "rust-toolchain.toml"))
	if err != nil {
		return ci.Detection{}, err
	}
	if ch := tomlChannel(t); ch != "" {
		return ci.Detection{Language: "rust", Version: ch, Source: "rust-toolchain.toml"}, nil
	}
	leg, err := readIfExists(filepath.Join(dir, "rust-toolchain"))
	if err != nil {
		return ci.Detection{}, err
	}
	if strings.Contains(leg, "[toolchain]") {
		if ch := tomlChannel(leg); ch != "" {
			return ci.Detection{Language: "rust", Version: ch, Source: "rust-toolchain"}, nil
		}
	} else {
		for _, l := range strings.Split(leg, "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				return ci.Detection{Language: "rust", Version: l, Source: "rust-toolchain"}, nil
			}
		}
	}
	if defaults["RUST_DEFAULT"] == "" {
		return ci.Detection{}, errors.New("RUST_DEFAULT is empty")
	}
	return ci.Detection{Language: "rust", Version: defaults["RUST_DEFAULT"], Source: "default"}, nil
}

// Toolchain returns the installed rustc version.
func (Rust) Toolchain(ctx context.Context, run func(ctx context.Context, argv ...string) (string, error)) (string, error) {
	out, err := run(ctx, "rustc", "--version")
	if err != nil {
		return "", fmt.Errorf("rustc --version: %w", err)
	}
	f := strings.Fields(out)
	if len(f) < 2 {
		return "", fmt.Errorf("rustc --version: unexpected output %q", strings.TrimSpace(out))
	}
	return f[1], nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// hasLib reports whether the package has a lib target: src/lib.rs or a [lib] table.
func hasLib(dir string) (bool, error) {
	if exists(filepath.Join(dir, "src", "lib.rs")) {
		return true, nil
	}
	m, err := readIfExists(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		return false, err
	}
	for _, l := range strings.Split(m, "\n") {
		if strings.TrimSpace(stripComment(l)) == "[lib]" {
			return true, nil
		}
	}
	return false, nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Steps returns install, lint, test and build.
func (Rust) Steps(ctx context.Context, env ci.Env, _ ci.Detection, cfg policy.CIConfig) ([]ci.Step, error) {
	to := cfg.Timeouts.PerStep
	if to == 0 {
		to = defaultTO
	}
	var locked []string
	if exists(filepath.Join(env.Dir, "Cargo.lock")) {
		locked = []string{"--locked"}
	}
	cargo := func(args ...string) ci.Cmd {
		return ci.Cmd{Argv: append(append([]string{"cargo"}, args...), locked...)}
	}

	steps := []ci.Step{{Name: "install", Timeout: to, Cmds: []ci.Cmd{
		// the official rust image ships without clippy and rustfmt
		{Shell: "if command -v rustup >/dev/null 2>&1; then rustup component add clippy rustfmt; fi"},
		cargo("fetch"),
	}}}

	// add builds a step: a disabled step is skipped, a run override replaces the default
	// commands (and drops their junit/coverage), and defaults are computed only when used.
	add := func(name ci.StepName, sc policy.CIStep, def func() (ci.Step, error)) error {
		s := ci.Step{Name: name, Timeout: to}
		switch {
		case !sc.On():
			s.Skip = "disabled in config"
		case sc.Run != "":
			s.Cmds = []ci.Cmd{{Shell: sc.Run}}
		default:
			d, err := def()
			if err != nil {
				return err
			}
			d.Name, d.Timeout = name, to
			s = d
		}
		if s.Skip == "" {
			if len(sc.JUnit) > 0 {
				s.JUnit = sc.JUnit
			}
			if sc.Coverage != "" {
				s.Coverage = sc.Coverage
			}
		}
		steps = append(steps, s)
		return nil
	}

	if err := add("lint", cfg.Steps.Lint, func() (ci.Step, error) {
		clippy := ci.Cmd{Argv: append(append([]string{"cargo", "clippy", "--all-targets"}, locked...), "--", "-D", "warnings")}
		return ci.Step{Cmds: []ci.Cmd{
			{Argv: []string{"cargo", "fmt", "--check"}},
			clippy,
		}}, nil
	}); err != nil {
		return nil, err
	}
	if err := add("test", cfg.Steps.Test, func() (ci.Step, error) {
		nextest, err := env.Tools(ctx, "cargo-nextest")
		if err != nil {
			return ci.Step{}, fmt.Errorf("fetch cargo-nextest: %w", err)
		}
		lib, err := hasLib(env.Dir)
		if err != nil {
			return ci.Step{}, err
		}
		// nextest requires an absolute tool-config path, so the run resolves it from $PWD.
		run := shQuote(nextest) + " nextest run --profile ci --tool-config-file \"shipguard:$PWD/" + nextestConfigPath + "\""
		if len(locked) > 0 {
			run += " --locked"
		}
		cmds := []ci.Cmd{
			{Shell: "mkdir -p .shipguard/ci && printf '%s' " + shQuote(nextestConfig) + " > " + nextestConfigPath},
			{Shell: run},
		}
		if lib {
			cmds = append(cmds, cargo("test", "--doc"))
		}
		return ci.Step{Cmds: cmds, JUnit: []string{"target/nextest/ci/junit.xml"}}, nil
	}); err != nil {
		return nil, err
	}
	if err := add("build", cfg.Steps.Build, func() (ci.Step, error) {
		return ci.Step{Cmds: []ci.Cmd{cargo("build", "--release")}}, nil
	}); err != nil {
		return nil, err
	}
	return steps, nil
}
