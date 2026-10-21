// Package ruby implements the Ruby language defaults for `shipguard ci`.
package ruby

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/policy"
)

const defaultTO = 30 * time.Minute

// Ruby is the Ruby language.
type Ruby struct{}

// Name returns "ruby".
func (Ruby) Name() string { return "ruby" }

// Markers returns the files that identify a Ruby project.
func (Ruby) Markers() []string { return []string{"Gemfile"} }

var gemfileRubyRe = regexp.MustCompile(`^\s*ruby\s+["'](\d[^"']*)["']`)

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

// Detect reads the Ruby version from .ruby-version, the Gemfile ruby directive, or the default.
func (Ruby) Detect(dir string, defaults map[string]string) (ci.Detection, error) {
	rv, err := readIfExists(filepath.Join(dir, ".ruby-version"))
	if err != nil {
		return ci.Detection{}, err
	}
	for _, l := range strings.Split(rv, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		return ci.Detection{Language: "ruby", Version: strings.TrimPrefix(l, "ruby-"), Source: ".ruby-version"}, nil
	}
	gf, err := readIfExists(filepath.Join(dir, "Gemfile"))
	if err != nil {
		return ci.Detection{}, err
	}
	for _, l := range strings.Split(gf, "\n") {
		if m := gemfileRubyRe.FindStringSubmatch(l); m != nil {
			return ci.Detection{Language: "ruby", Version: m[1], Source: "Gemfile"}, nil
		}
	}
	if defaults["RUBY_DEFAULT"] == "" {
		return ci.Detection{}, errors.New("RUBY_DEFAULT is empty")
	}
	return ci.Detection{Language: "ruby", Version: defaults["RUBY_DEFAULT"], Source: "default"}, nil
}

// Toolchain returns the installed Ruby version.
func (Ruby) Toolchain(ctx context.Context, run func(ctx context.Context, argv ...string) (string, error)) (string, error) {
	out, err := run(ctx, "ruby", "-e", "print RUBY_VERSION")
	if err != nil {
		return "", fmt.Errorf("ruby -e 'print RUBY_VERSION': %w", err)
	}
	return strings.TrimSpace(out), nil
}

// lockedGems returns the gems listed as specs under the GEM section of Gemfile.lock
// (lines indented exactly four spaces: "    name (version)").
func lockedGems(lock string) map[string]bool {
	gems := map[string]bool{}
	section, inSpecs := "", false
	for _, l := range strings.Split(lock, "\n") {
		l = strings.TrimRight(l, "\r")
		if l != "" && l[0] != ' ' {
			section, inSpecs = l, false
			continue
		}
		if section != "GEM" {
			continue
		}
		if strings.TrimSpace(l) == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs && strings.HasPrefix(l, "    ") && !strings.HasPrefix(l, "     ") {
			if f := strings.Fields(l); len(f) > 0 {
				gems[f[0]] = true
			}
		}
	}
	return gems
}

// Steps returns install, lint, test and build.
func (Ruby) Steps(_ context.Context, env ci.Env, _ ci.Detection, cfg policy.CIConfig) ([]ci.Step, error) {
	to := cfg.Timeouts.PerStep
	if to == 0 {
		to = defaultTO
	}
	lock, err := os.ReadFile(filepath.Join(env.Dir, "Gemfile.lock"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("Gemfile.lock is missing; commit it (bundle lock)")
	}
	if err != nil {
		return nil, fmt.Errorf("read Gemfile.lock: %w", err)
	}
	gems := lockedGems(string(lock))

	steps := []ci.Step{{Name: "install", Timeout: to, Cmds: []ci.Cmd{
		{Argv: []string{"bundle", "config", "set", "--local", "frozen", "true"}},
		{Argv: []string{"bundle", "install"}},
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
		if !gems["rubocop"] {
			return ci.Step{Skip: "rubocop not in Gemfile.lock"}, nil
		}
		return ci.Step{Cmds: []ci.Cmd{{Argv: []string{"bundle", "exec", "rubocop"}}}}, nil
	}); err != nil {
		return nil, err
	}
	if err := add("test", cfg.Steps.Test, func() (ci.Step, error) {
		if fi, err := os.Stat(filepath.Join(env.Dir, "spec")); err == nil && fi.IsDir() && gems["rspec-core"] {
			return ci.Step{Cmds: []ci.Cmd{{Argv: []string{"bundle", "exec", "rspec"}}}}, nil
		}
		if gems["rake"] {
			return ci.Step{Cmds: []ci.Cmd{{Argv: []string{"bundle", "exec", "rake", "test"}}}}, nil
		}
		return ci.Step{Skip: "no rspec or rake test found"}, nil
	}); err != nil {
		return nil, err
	}
	if err := add("build", cfg.Steps.Build, func() (ci.Step, error) {
		specs, err := filepath.Glob(filepath.Join(env.Dir, "*.gemspec"))
		if err != nil {
			return ci.Step{}, fmt.Errorf("find gemspec: %w", err)
		}
		switch len(specs) {
		case 0:
			return ci.Step{Skip: "no gemspec"}, nil
		case 1:
			return ci.Step{Cmds: []ci.Cmd{{Argv: []string{"gem", "build", filepath.Base(specs[0])}}}}, nil
		}
		names := make([]string, len(specs))
		for i, s := range specs {
			names[i] = filepath.Base(s)
		}
		return ci.Step{}, fmt.Errorf("multiple gemspecs found (%s); set ci.steps.build.run", strings.Join(names, ", "))
	}); err != nil {
		return nil, err
	}
	return steps, nil
}
