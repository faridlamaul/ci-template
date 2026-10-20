package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/scanner"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestVersionPrintsVersion(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"version"}, envOf(nil), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "dev") {
		t.Fatalf("stdout = %q, want it to contain dev", out.String())
	}
}

func TestUnknownCommandIsError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"nope"}, envOf(nil), &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestStubsExitWithError(t *testing.T) {
	for _, c := range []string{"gate", "report", "run"} {
		var out, errb bytes.Buffer
		if code := run([]string{c}, envOf(nil), &out, &errb); code != 2 {
			t.Errorf("%s: exit = %d, want 2", c, code)
		}
	}
}

func TestFlagEnvPrecedence(t *testing.T) {
	tests := []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{"flag", []string{"--mode", "audit"}, nil, "audit"},
		{"flag beats env", []string{"--mode", "audit"}, map[string]string{"SHIPGUARD_MODE": "enforce", "BITBUCKET_BUILD_NUMBER": "1", "MODE": "enforce"}, "audit"},
		{"shipguard env", nil, map[string]string{"SHIPGUARD_MODE": "audit"}, "audit"},
		{"bare ignored outside bitbucket", nil, map[string]string{"MODE": "audit"}, ""},
		{"bare on bitbucket", nil, map[string]string{"MODE": "audit", "BITBUCKET_BUILD_NUMBER": "1"}, "audit"},
		{"shipguard env beats bare", nil, map[string]string{"SHIPGUARD_MODE": "audit", "MODE": "enforce", "BITBUCKET_BUILD_NUMBER": "1"}, "audit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			root, g := newRoot(envOf(tt.env), &out, &errb)
			root.SetArgs(append([]string{"version"}, tt.args...))
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if g.mode != tt.want {
				t.Fatalf("mode = %q, want %q", g.mode, tt.want)
			}
		})
	}
}

func TestBareScannersOnBitbucket(t *testing.T) {
	var out, errb bytes.Buffer
	root, g := newRoot(envOf(map[string]string{"SCANNERS": "secrets,sast", "BITBUCKET_BUILD_NUMBER": "1"}), &out, &errb)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if g.scanners != "secrets,sast" {
		t.Fatalf("scanners = %q", g.scanners)
	}
}

func TestDirDefaultResolution(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"github", map[string]string{"GITHUB_WORKSPACE": "/gh", "CI_PROJECT_DIR": "/gl", "BITBUCKET_CLONE_DIR": "/bb"}, "/gh"},
		{"gitlab", map[string]string{"CI_PROJECT_DIR": "/gl", "BITBUCKET_CLONE_DIR": "/bb"}, "/gl"},
		{"bitbucket", map[string]string{"BITBUCKET_CLONE_DIR": "/bb"}, "/bb"},
		{"env override", map[string]string{"GITHUB_WORKSPACE": "/gh", "SHIPGUARD_DIR": "/x"}, "/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			root, g := newRoot(envOf(tt.env), &out, &errb)
			root.SetArgs([]string{"version"})
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if g.dir != tt.want {
				t.Fatalf("dir = %q, want %q", g.dir, tt.want)
			}
		})
	}
	t.Run("cwd fallback", func(t *testing.T) {
		var out, errb bytes.Buffer
		root, g := newRoot(envOf(nil), &out, &errb)
		root.SetArgs([]string{"version"})
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		if g.dir == "" {
			t.Fatal("dir is empty")
		}
	})
}

type failing struct{ dirs *[]string }

func (failing) Name() string               { return "opengrep" }
func (failing) Category() finding.Category { return finding.CategorySAST }
func (f failing) Scan(_ context.Context, t scanner.Target) ([]finding.Finding, error) {
	*f.dirs = append(*f.dirs, t.Dir)
	return nil, errors.New("opengrep exited with code 2")
}

// fakeScanners swaps the real scanners for one failing SAST scanner and
// records the rules dir it was built with.
func fakeScanners(t *testing.T, rulesDir *string, dirs *[]string) {
	t.Helper()
	old := buildScanners
	buildScanners = func(r string) []scanner.Scanner {
		*rulesDir = r
		return []scanner.Scanner{failing{dirs: dirs}}
	}
	t.Cleanup(func() { buildScanners = old })
}

func TestScanScannerErrorExitsZero(t *testing.T) {
	var rules string
	var dirs []string
	fakeScanners(t, &rules, &dirs)
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--dir", dir}, envOf(nil), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	if rules != defaultRulesDir || len(dirs) != 1 || dirs[0] != dir {
		t.Errorf("rules = %q, dirs = %q", rules, dirs)
	}
	res, err := finding.ReadResult(filepath.Join(dir, ".shipguard", "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Scanners) != 1 || res.Scanners[0].Status != "error" || res.Scanners[0].Error == "" {
		t.Errorf("scanners = %+v, want one error run", res.Scanners)
	}
	if res.ShipguardVersion != version {
		t.Errorf("version = %q", res.ShipguardVersion)
	}
	if !strings.Contains(errb.String(), "opengrep failed") {
		t.Errorf("stderr = %q, want a scanner warning", errb.String())
	}
}

func TestScanRulesDirFromEnv(t *testing.T) {
	var rules string
	var dirs []string
	fakeScanners(t, &rules, &dirs)
	var out, errb bytes.Buffer
	env := envOf(map[string]string{"SHIPGUARD_RULES_DIR": "/custom/rules"})
	if code := run([]string{"scan", "--dir", t.TempDir()}, env, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	if rules != "/custom/rules" {
		t.Errorf("rules = %q", rules)
	}
}

func TestScanConfigErrorsExitTwo(t *testing.T) {
	var rules string
	var dirs []string
	fakeScanners(t, &rules, &dirs)
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, ".shipguard.yaml"), []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		env  map[string]string
	}{
		{"unknown scanner", []string{"--scanners", "sast,bogus"}, nil},
		{"empty scanner list", []string{"--scanners", ","}, nil},
		{"bad mode", []string{"--mode", "warn"}, nil},
		{"invalid config", []string{"--dir", bad}, nil},
		{"pr base missing", nil, map[string]string{"SHIPGUARD_EVENT": "pr"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"scan", "--dir", t.TempDir()}, tt.args...)
			var out, errb bytes.Buffer
			if code := run(args, envOf(tt.env), &out, &errb); code != 2 {
				t.Fatalf("exit = %d, want 2; stderr = %s", code, errb.String())
			}
		})
	}
	if len(dirs) != 0 {
		t.Errorf("scanners ran on a config error: %q", dirs)
	}
}
