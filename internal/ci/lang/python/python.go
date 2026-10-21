// Package python implements the Python language defaults for `shipguard ci`.
package python

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/policy"
)

const (
	defaultTO = 30 * time.Minute
	venvPy    = ".venv/bin/python"
	junitXML  = ".shipguard/ci/junit-python.xml"
	covXML    = ".shipguard/ci/coverage.xml"
)

// Python is the Python language.
type Python struct{}

// Name returns "python".
func (Python) Name() string { return "python" }

// Markers returns the files that identify a Python project. They count as one marker set.
func (Python) Markers() []string { return []string{"pyproject.toml", "requirements.txt"} }

type pyProject struct {
	requiresPython string
	buildSystem    bool
}

var (
	tableRe = regexp.MustCompile(`^\[\[?\s*([^\]]*?)\s*\]\]?\s*(#.*)?$`)
	keyRe   = regexp.MustCompile(`^requires-python\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

// readPyproject extracts the two facts shipguard needs from pyproject.toml with a
// line-based reader: [project] requires-python (single-line basic or literal string) and
// the presence of a [build-system] table. It is not a TOML parser: multi-line strings and
// dotted or inline-table forms (project.requires-python = ..., project = {...}) are not
// understood. A missing file yields the zero value.
func readPyproject(dir string) (pyProject, error) {
	var p pyProject
	b, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, fmt.Errorf("read pyproject.toml: %w", err)
	}
	table := ""
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if m := tableRe.FindStringSubmatch(l); m != nil {
			table = m[1]
			if table == "build-system" {
				p.buildSystem = true
			}
			continue
		}
		if table == "project" {
			if m := keyRe.FindStringSubmatch(l); m != nil {
				p.requiresPython = strings.TrimSpace(m[1] + m[2])
			}
		}
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

// Detect reads the Python version from .python-version, requires-python, or the default.
func (Python) Detect(dir string, defaults map[string]string) (ci.Detection, error) {
	v, err := versionFile(filepath.Join(dir, ".python-version"))
	if err != nil {
		return ci.Detection{}, err
	}
	if v != "" {
		return ci.Detection{Language: "python", Version: v, Source: ".python-version"}, nil
	}
	cands := strings.Fields(defaults["PYTHON_DEFAULTS"])
	if len(cands) == 0 {
		return ci.Detection{}, errors.New("PYTHON_DEFAULTS is empty")
	}
	pp, err := readPyproject(dir)
	if err != nil {
		return ci.Detection{}, err
	}
	if pp.requiresPython == "" {
		return ci.Detection{Language: "python", Version: cands[0], Source: "default"}, nil
	}
	best, err := resolve(pp.requiresPython, cands)
	if err != nil {
		return ci.Detection{}, err
	}
	return ci.Detection{Language: "python", Version: best, Source: "pyproject.toml"}, nil
}

// Toolchain returns the installed Python version.
func (Python) Toolchain(ctx context.Context, run func(ctx context.Context, argv ...string) (string, error)) (string, error) {
	out, err := run(ctx, "python3", "--version")
	if err != nil {
		return "", fmt.Errorf("python3 --version: %w", err)
	}
	f := strings.Fields(out)
	if len(f) < 2 {
		return "", fmt.Errorf("python3 --version: unexpected output %q", strings.TrimSpace(out))
	}
	return f[1], nil
}

type ver []int

func parseVer(s string) (ver, error) {
	var v ver
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid version %q", s)
		}
		v = append(v, n)
	}
	return v, nil
}

func cmp(a, b ver) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func hasPrefix(v, prefix ver) bool {
	if len(v) < len(prefix) {
		v = append(append(ver{}, v...), make(ver, len(prefix)-len(v))...)
	}
	return cmp(v[:len(prefix)], prefix) == 0
}

var clauseRe = regexp.MustCompile(`^(>=|<=|==|~=|>|<)\s*(\d+(?:\.\d+)*(?:\.\*)?)$`)

// matches reports whether candidate (e.g. "3.12") satisfies one clause. The candidate is
// compared as a padded release tuple, so ">=3.11.2" rejects "3.11".
func matches(cl, cand string) (bool, error) {
	m := clauseRe.FindStringSubmatch(cl)
	if m == nil {
		return false, fmt.Errorf("unsupported specifier %q", cl)
	}
	op, rhs := m[1], m[2]
	star := strings.HasSuffix(rhs, ".*")
	if star && op != "==" {
		return false, fmt.Errorf("unsupported specifier %q", cl)
	}
	v, err := parseVer(strings.TrimSuffix(rhs, ".*"))
	if err != nil {
		return false, fmt.Errorf("unsupported specifier %q", cl)
	}
	c, err := parseVer(cand)
	if err != nil {
		return false, err
	}
	switch op {
	case ">=":
		return cmp(c, v) >= 0, nil
	case ">":
		return cmp(c, v) > 0, nil
	case "<":
		return cmp(c, v) < 0, nil
	case "<=":
		return cmp(c, v) <= 0, nil
	case "==":
		if star {
			return hasPrefix(c, v), nil
		}
		return cmp(c, v) == 0, nil
	default: // ~=
		if len(v) < 2 {
			return false, fmt.Errorf("unsupported specifier %q", cl)
		}
		return cmp(c, v) >= 0 && hasPrefix(c, v[:len(v)-1]), nil
	}
}

// resolve returns the highest candidate satisfying every comma-joined clause of spec.
func resolve(spec string, cands []string) (string, error) {
	var clauses []string
	for _, cl := range strings.Split(spec, ",") {
		if cl = strings.TrimSpace(cl); cl != "" {
			clauses = append(clauses, cl)
		}
	}
	if len(clauses) == 0 {
		return "", fmt.Errorf("unsupported specifier %q", spec)
	}
	best := ""
	var bestV ver
	for _, cand := range cands {
		ok := true
		for _, cl := range clauses {
			m, err := matches(cl, cand)
			if err != nil {
				return "", fmt.Errorf("requires-python %q: %w", spec, err)
			}
			ok = ok && m
		}
		if !ok {
			continue
		}
		cv, _ := parseVer(cand)
		if best == "" || cmp(cv, bestV) > 0 {
			best, bestV = cand, cv
		}
	}
	if best == "" {
		return "", fmt.Errorf("requires-python %q is not satisfied by any default (%s)", spec, strings.Join(cands, " "))
	}
	return best, nil
}

func exists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Steps returns install, lint, test and build.
func (Python) Steps(ctx context.Context, env ci.Env, _ ci.Detection, cfg policy.CIConfig) ([]ci.Step, error) {
	to := cfg.Timeouts.PerStep
	if to == 0 {
		to = defaultTO
	}
	pp, err := readPyproject(env.Dir)
	if err != nil {
		return nil, err
	}
	pytestV, covV, poetryV := env.Defaults["PYTEST_VERSION"], env.Defaults["COVERAGE_VERSION"], env.Defaults["POETRY_VERSION"]
	if pytestV == "" || covV == "" {
		return nil, errors.New("PYTEST_VERSION and COVERAGE_VERSION defaults are required")
	}

	uv, err := env.Tools(ctx, "uv")
	if err != nil {
		return nil, fmt.Errorf("uv: %w", err)
	}

	// Every uv command uses the toolchain interpreter the CLI checks (python3 on PATH),
	// never a uv-managed or downloaded one.
	uvEnv := func(extra ...string) map[string]string {
		m := map[string]string{"UV_PYTHON": "python3", "UV_PYTHON_DOWNLOADS": "never"}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i]] = extra[i+1]
		}
		return m
	}

	var install []ci.Cmd
	switch {
	case exists(env.Dir, "uv.lock"):
		install = []ci.Cmd{{Argv: []string{uv, "sync", "--frozen"}, Env: uvEnv()}}
	case exists(env.Dir, "poetry.lock"):
		if poetryV == "" {
			return nil, errors.New("POETRY_VERSION default is required")
		}
		install = []ci.Cmd{{
			Argv: []string{uv, "tool", "run", "--from", "poetry==" + poetryV, "poetry", "install", "--sync"},
			Env:  uvEnv("POETRY_VIRTUALENVS_IN_PROJECT", "true"),
		}}
	case exists(env.Dir, "requirements.txt"):
		pip := []string{uv, "pip", "install", "--python", venvPy, "-r", "requirements.txt"}
		if exists(env.Dir, "requirements-dev.txt") {
			pip = append(pip, "-r", "requirements-dev.txt")
		}
		install = []ci.Cmd{{Argv: []string{uv, "venv", ".venv"}, Env: uvEnv()}, {Argv: pip, Env: uvEnv()}}
	default:
		return nil, errors.New("no lockfile found (uv.lock, poetry.lock or requirements.txt)")
	}
	for _, p := range [][2]string{{"pytest", pytestV}, {"coverage", covV}} {
		install = append(install, ci.Cmd{Shell: fmt.Sprintf("%s -c 'import %s' 2>/dev/null || %s pip install --python %s %s==%s",
			venvPy, p[0], shQuote(uv), venvPy, p[0], p[1]), Env: uvEnv()})
	}
	steps := []ci.Step{{Name: "install", Cmds: install, Timeout: to}}

	// add builds a step: a disabled step is skipped, a run override replaces the default
	// commands (and drops their junit/coverage), and tools are fetched only for defaults.
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
		ruff, err := env.Tools(ctx, "ruff")
		if err != nil {
			return ci.Step{}, fmt.Errorf("ruff: %w", err)
		}
		return ci.Step{Cmds: []ci.Cmd{
			{Argv: []string{ruff, "check", "."}},
			{Argv: []string{ruff, "format", "--check", "."}},
		}}, nil
	}); err != nil {
		return nil, err
	}
	if err := add("test", cfg.Steps.Test, func() (ci.Step, error) {
		return ci.Step{
			Cmds: []ci.Cmd{
				{Argv: []string{"mkdir", "-p", ".shipguard/ci"}},
				{Argv: []string{".venv/bin/coverage", "run", "-m", "pytest", "--junitxml=" + junitXML}},
				{Argv: []string{".venv/bin/coverage", "xml", "-o", covXML}},
			},
			JUnit:    []string{junitXML},
			Coverage: covXML,
		}, nil
	}); err != nil {
		return nil, err
	}
	if err := add("build", cfg.Steps.Build, func() (ci.Step, error) {
		if !pp.buildSystem {
			return ci.Step{Skip: "no [build-system] in pyproject.toml"}, nil
		}
		return ci.Step{Cmds: []ci.Cmd{{Argv: []string{uv, "build"}}}}, nil
	}); err != nil {
		return nil, err
	}
	return steps, nil
}
