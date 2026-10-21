package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/policy"
)

// fakeLang is a language whose steps are shell snippets.
type fakeLang struct {
	steps        map[ci.StepName]string // shell per step; "" = skipped
	version      string
	installed    string
	toolchainErr error
	stepsErr     error
	gotCfg       *policy.CIConfig
}

func (f *fakeLang) Name() string      { return "fake" }
func (f *fakeLang) Markers() []string { return []string{"fake.marker"} }
func (f *fakeLang) Detect(string, map[string]string) (ci.Detection, error) {
	return ci.Detection{Language: "fake", Version: f.version, Source: "fake.marker"}, nil
}
func (f *fakeLang) Toolchain(context.Context, func(context.Context, ...string) (string, error)) (string, error) {
	return f.installed, f.toolchainErr
}
func (f *fakeLang) Steps(_ context.Context, _ ci.Env, _ ci.Detection, cfg policy.CIConfig) ([]ci.Step, error) {
	f.gotCfg = &cfg
	if f.stepsErr != nil {
		return nil, f.stepsErr
	}
	var out []ci.Step
	for _, n := range []ci.StepName{"install", "lint", "test", "build"} {
		s := ci.Step{Name: n}
		if sh := f.steps[n]; sh != "" {
			s.Cmds = []ci.Cmd{{Shell: sh}}
		} else {
			s.Skip = "not configured"
		}
		out = append(out, s)
	}
	return out, nil
}

func setupCI(t *testing.T, l *fakeLang, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	if err := os.WriteFile(filepath.Join(dir, "fake.marker"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for p, c := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldL, oldT := ciLanguages, ciToolResolver
	ciLanguages = func() []ci.Language { return []ci.Language{l} }
	ciToolResolver = func(string) (func(context.Context, string) (string, error), map[string]string, error) {
		return func(context.Context, string) (string, error) { return "/tools/x", nil }, map[string]string{}, nil
	}
	t.Cleanup(func() { ciLanguages, ciToolResolver = oldL, oldT })
	return dir
}

func runCI(dir string, env map[string]string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := execute(context.Background(), append([]string{"ci", "--dir", dir}, args...), envOf(env), &out, &errb)
	return code, out.String(), errb.String()
}

func TestCIExitCodes(t *testing.T) {
	all := func(sh string) map[ci.StepName]string {
		return map[ci.StepName]string{"install": "true", "lint": sh, "test": sh, "build": sh}
	}
	tests := []struct {
		name  string
		l     *fakeLang
		want  int
		extra string
	}{
		{"pass", &fakeLang{steps: all("true")}, 0, ""},
		{"step fails", &fakeLang{steps: all("exit 3")}, 1, ""},
		{"all skipped", &fakeLang{steps: map[ci.StepName]string{}}, 2, ""},
		{"steps error", &fakeLang{stepsErr: errors.New("tool boom")}, 2, "error: tool boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := setupCI(t, tt.l, nil)
			code, _, stderr := runCI(dir, nil)
			if code != tt.want {
				t.Fatalf("exit = %d, want %d; stderr=%s", code, tt.want, stderr)
			}
			if tt.extra != "" && strings.Count(stderr, tt.extra) != 1 {
				t.Fatalf("stderr = %q, want %q once", stderr, tt.extra)
			}
		})
	}
	t.Run("detection error", func(t *testing.T) {
		dir := setupCI(t, &fakeLang{}, nil)
		if err := os.Remove(filepath.Join(dir, "fake.marker")); err != nil {
			t.Fatal(err)
		}
		if code, _, stderr := runCI(dir, nil); code != 2 || strings.Count(stderr, "error:") != 1 {
			t.Fatalf("exit = %d, stderr = %q", code, stderr)
		}
	})
	t.Run("tool load error", func(t *testing.T) {
		dir := setupCI(t, &fakeLang{steps: all("true")}, nil)
		ciToolResolver = func(string) (func(context.Context, string) (string, error), map[string]string, error) {
			return nil, nil, errors.New("no tools")
		}
		if code, _, _ := runCI(dir, nil); code != 2 {
			t.Fatalf("exit = %d, want 2", code)
		}
	})
	t.Run("unknown step", func(t *testing.T) {
		dir := setupCI(t, &fakeLang{steps: all("true")}, nil)
		if code, _, _ := runCI(dir, nil, "deploy"); code != 2 {
			t.Fatalf("exit = %d, want 2", code)
		}
	})
}

func TestCIWritesResults(t *testing.T) {
	l := &fakeLang{steps: map[ci.StepName]string{"install": "true", "test": "true"}}
	dir := setupCI(t, l, nil)
	if code, _, stderr := runCI(dir, nil); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".shipguard", "ci", "result.json")); err != nil {
		t.Fatal(err)
	}
}

func TestToolchainMismatch(t *testing.T) {
	steps := map[ci.StepName]string{"install": "true", "test": "true"}
	t.Run("version differs", func(t *testing.T) {
		dir := setupCI(t, &fakeLang{steps: steps, version: "1.21", installed: "1.22.3"}, nil)
		code, _, stderr := runCI(dir, nil)
		if code != 0 {
			t.Fatalf("exit = %d", code)
		}
		if !strings.Contains(stderr, "warning: fake 1.21 requested but 1.22.3 is installed") {
			t.Fatalf("stderr = %q", stderr)
		}
		b, _ := os.ReadFile(filepath.Join(dir, ".shipguard", "ci", "result.json"))
		if !strings.Contains(string(b), "requested but 1.22.3 is installed") {
			t.Fatalf("result.json lacks warning: %s", b)
		}
	})
	t.Run("same major.minor or range", func(t *testing.T) {
		for _, v := range []string{"1.22", "1", ">=1.20", "stable"} {
			dir := setupCI(t, &fakeLang{steps: steps, version: v, installed: "1.22.3"}, nil)
			if _, _, stderr := runCI(dir, nil); strings.Contains(stderr, "warning:") {
				t.Fatalf("version %q: stderr = %q", v, stderr)
			}
		}
	})
	t.Run("missing", func(t *testing.T) {
		dir := setupCI(t, &fakeLang{steps: steps, toolchainErr: errors.New("exec: not found")}, nil)
		code, _, stderr := runCI(dir, nil)
		if code != 2 || !strings.Contains(stderr, "toolchain fake not found") {
			t.Fatalf("exit = %d, stderr = %q", code, stderr)
		}
	})
}

func TestCIDetectJSON(t *testing.T) {
	dir := setupCI(t, &fakeLang{version: "1.22"}, nil)
	var out, errb bytes.Buffer
	code := execute(context.Background(), []string{"ci", "detect", "--dir", dir, "--format", "json"}, envOf(nil), &out, &errb)
	want := `{"language":"fake","version":"1.22","source":"fake.marker"}` + "\n"
	if code != 0 || out.String() != want {
		t.Fatalf("exit = %d, out = %q, err = %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := execute(context.Background(), []string{"ci", "detect", "--dir", dir}, envOf(nil), &out, &errb); code != 0 || out.String() != "fake 1.22 (fake.marker)\n" {
		t.Fatalf("exit = %d, out = %q", code, out.String())
	}
}

func TestCIUsesHeadConfig(t *testing.T) {
	l := &fakeLang{steps: map[ci.StepName]string{"install": "true", "test": "true"}}
	dir := setupCI(t, l, map[string]string{
		".shipguard.yaml":        "ci:\n  timeouts:\n    per_step: 7m\n",
		".shipguard/policy.yaml": "ci:\n  timeouts:\n    per_step: 3m\n",
	})
	if code, _, stderr := runCI(dir, nil); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if l.gotCfg.Timeouts.PerStep.Minutes() != 7 {
		t.Fatalf("per_step = %v, want 7m", l.gotCfg.Timeouts.PerStep)
	}
}

func TestCIFlagOverrides(t *testing.T) {
	l := &fakeLang{steps: map[ci.StepName]string{"install": "true", "test": "true"}}
	dir := setupCI(t, l, nil)
	if code, _, stderr := runCI(dir, map[string]string{"SHIPGUARD_TOOLCHAIN": "9.9"}, "--language", "fake"); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	if l.gotCfg.Language != "fake" || l.gotCfg.Version != "9.9" {
		t.Fatalf("cfg = %+v", l.gotCfg)
	}
}

func TestCIStepArgs(t *testing.T) {
	sh := func(n string) string { return "echo ran-" + n }
	l := &fakeLang{steps: map[ci.StepName]string{"install": sh("install"), "lint": sh("lint"), "test": sh("test"), "build": sh("build")}}
	dir := setupCI(t, l, nil)
	code, out, stderr := runCI(dir, nil, "test", "test")
	if code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr)
	}
	for _, n := range []string{"install", "test"} {
		if !strings.Contains(out, "ran-"+n) {
			t.Errorf("missing %s: %s", n, out)
		}
	}
	for _, n := range []string{"lint", "build"} {
		if strings.Contains(out, "ran-"+n) {
			t.Errorf("%s ran: %s", n, out)
		}
	}
	if i, j := strings.Index(out, "ran-install"), strings.Index(out, "ran-test"); i > j {
		t.Errorf("order: %s", out)
	}
}
