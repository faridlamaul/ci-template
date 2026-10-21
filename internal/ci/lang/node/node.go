// Package node implements the Node.js language defaults for `shipguard ci`.
package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/policy"
)

const defaultTO = 30 * time.Minute

// Node is the Node.js language.
type Node struct{}

// Name returns "node".
func (Node) Name() string { return "node" }

// Markers returns the files that identify a Node project.
func (Node) Markers() []string { return []string{"package.json"} }

type pkgJSON struct {
	Engines        struct{ Node string } `json:"engines"`
	PackageManager string                `json:"packageManager"`
	Scripts        map[string]any        `json:"scripts"`
}

func readPkg(dir string) (pkgJSON, error) {
	var p pkgJSON
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return p, fmt.Errorf("read package.json: %w", err)
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("parse package.json: %w", err)
	}
	return p, nil
}

// versionFile returns the first non-empty, non-comment line of a version file.
func versionFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			return l, nil
		}
	}
	return "", nil
}

// Detect reads the Node version from .nvmrc, .node-version, engines.node, or the default.
func (Node) Detect(dir string, defaults map[string]string) (ci.Detection, error) {
	pkg, err := readPkg(dir)
	if err != nil {
		return ci.Detection{}, err
	}
	for _, f := range []string{".nvmrc", ".node-version"} {
		v, err := versionFile(filepath.Join(dir, f))
		if err != nil {
			return ci.Detection{}, err
		}
		if v == "" {
			continue
		}
		low := strings.ToLower(v)
		switch {
		case strings.HasPrefix(low, "lts/"), low == "node", low == "stable", low == "latest":
			return ci.Detection{Language: "node", Version: defaults["NODE_DEFAULT"], Source: f}, nil
		}
		return ci.Detection{Language: "node", Version: strings.TrimPrefix(v, "v"), Source: f}, nil
	}
	if v := strings.TrimSpace(pkg.Engines.Node); v != "" {
		return ci.Detection{Language: "node", Version: v, Source: "package.json"}, nil
	}
	return ci.Detection{Language: "node", Version: defaults["NODE_DEFAULT"], Source: "default"}, nil
}

// Toolchain returns the installed Node version without the "v" prefix.
func (Node) Toolchain(ctx context.Context, run func(ctx context.Context, argv ...string) (string, error)) (string, error) {
	out, err := run(ctx, "node", "--version")
	if err != nil {
		return "", fmt.Errorf("node --version: %w", err)
	}
	return strings.TrimPrefix(strings.TrimSpace(out), "v"), nil
}

var lockfiles = []struct{ file, pm string }{
	{"package-lock.json", "npm"},
	{"pnpm-lock.yaml", "pnpm"},
	{"yarn.lock", "yarn"},
	{"bun.lock", "bun"},
	{"bun.lockb", "bun"},
}

// detectPM finds the package manager from the single lockfile present.
func detectPM(dir string, pkg pkgJSON) (string, error) {
	var found, names []string
	for _, l := range lockfiles {
		if _, err := os.Stat(filepath.Join(dir, l.file)); err == nil {
			found = append(found, l.pm)
			names = append(names, l.file)
		}
	}
	switch {
	case len(found) == 0:
		return "", errors.New("no lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock or bun.lockb)")
	case len(names) > 1:
		return "", fmt.Errorf("multiple lockfiles found: %s", strings.Join(names, ", "))
	}
	pm := found[0]
	if name, _, _ := strings.Cut(pkg.PackageManager, "@"); name != "" && name != pm {
		return "", fmt.Errorf("package.json packageManager is %q but the lockfile %s belongs to %s", name, names[0], pm)
	}
	return pm, nil
}

func yarnBerry(dir string, pkg pkgJSON) bool {
	if _, err := os.Stat(filepath.Join(dir, ".yarnrc.yml")); err == nil {
		return true
	}
	if v, ok := strings.CutPrefix(pkg.PackageManager, "yarn@"); ok {
		major, _, _ := strings.Cut(v, ".")
		n, err := strconv.Atoi(major)
		return err == nil && n >= 2
	}
	return false
}

// Steps returns install, lint, test and build.
func (Node) Steps(ctx context.Context, env ci.Env, _ ci.Detection, cfg policy.CIConfig) ([]ci.Step, error) {
	to := cfg.Timeouts.PerStep
	if to == 0 {
		to = defaultTO
	}
	pkg, err := readPkg(env.Dir)
	if err != nil {
		return nil, err
	}
	pm, err := detectPM(env.Dir, pkg)
	if err != nil {
		return nil, err
	}

	bin := pm
	if pm == "bun" {
		bin, err = env.Tools(ctx, "bun")
		if err != nil {
			return nil, fmt.Errorf("bun: %w", err)
		}
	}

	var install []ci.Cmd
	switch pm {
	case "npm":
		install = []ci.Cmd{{Argv: []string{"npm", "ci"}}}
	case "pnpm":
		install = []ci.Cmd{{Argv: []string{"corepack", "enable", "pnpm"}}, {Argv: []string{"pnpm", "install", "--frozen-lockfile"}}}
	case "yarn":
		flag := "--frozen-lockfile"
		if yarnBerry(env.Dir, pkg) {
			flag = "--immutable"
		}
		install = []ci.Cmd{{Argv: []string{"corepack", "enable", "yarn"}}, {Argv: []string{"yarn", "install", flag}}}
	case "bun":
		install = []ci.Cmd{{Argv: []string{bin, "install", "--frozen-lockfile"}}}
	}
	steps := []ci.Step{{Name: "install", Cmds: install, Timeout: to}}

	add := func(name ci.StepName, sc policy.CIStep) {
		s := ci.Step{Name: name, Timeout: to}
		switch {
		case !sc.On():
			s.Skip = "disabled in config"
		case sc.Run != "":
			s.Cmds = []ci.Cmd{{Shell: sc.Run}}
		default:
			if _, ok := pkg.Scripts[string(name)]; !ok {
				s.Skip = fmt.Sprintf("no %s script in package.json", name)
			} else {
				s.Cmds = []ci.Cmd{{Argv: []string{bin, "run", string(name)}}}
			}
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
	}
	add("lint", cfg.Steps.Lint)
	add("test", cfg.Steps.Test)
	add("build", cfg.Steps.Build)
	return steps, nil
}
