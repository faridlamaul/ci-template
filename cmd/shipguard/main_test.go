package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	for _, c := range []string{"report", "run"} {
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

// writeGateFixture writes findings.json (and optionally policy.yaml) in dir.
func writeGateFixture(t *testing.T, dir, event string, runs []finding.ScannerRun, fs []finding.Finding, policyYAML string) {
	t.Helper()
	out := filepath.Join(dir, ".shipguard")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	res := finding.Result{
		SchemaVersion: 1,
		Context:       json.RawMessage(`{"platform":"local","event":"` + event + `"}`),
		Scanners:      runs, Findings: fs,
	}
	if err := finding.WriteResult(filepath.Join(out, "findings.json"), res); err != nil {
		t.Fatal(err)
	}
	if policyYAML != "" {
		if err := os.WriteFile(filepath.Join(out, "policy.yaml"), []byte(policyYAML), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

var okRunFixture = []finding.ScannerRun{{Name: "opengrep", Category: finding.CategorySAST, Status: "ok"}}

func TestGateNoScannerRanFailsClosed(t *testing.T) {
	for name, runs := range map[string][]finding.ScannerRun{
		"empty":   nil,
		"skipped": {{Name: "opengrep", Status: "skipped"}},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeGateFixture(t, dir, "push", runs, nil, "")
			var out, errb bytes.Buffer
			if code := run([]string{"gate", "--dir", dir}, envOf(nil), &out, &errb); code != 2 {
				t.Fatalf("exit = %d, want 2", code)
			}
			if !strings.Contains(errb.String(), "no scanner ran") {
				t.Errorf("stderr = %q", errb.String())
			}
		})
	}
}

func TestGatePRWithoutPolicyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeGateFixture(t, dir, "pr", okRunFixture, nil, "")
	if err := os.WriteFile(filepath.Join(dir, ".shipguard.yaml"), []byte("mode: audit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"gate", "--dir", dir}, envOf(nil), &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2, stderr = %s", code, errb.String())
	}
}

func TestGateExitCodes(t *testing.T) {
	high := finding.Finding{ID: "R1", Category: finding.CategorySAST, Severity: finding.High, File: "a.go", Line: 1,
		Message: "bad", Fingerprint: "fp1"}
	newHigh := high
	newHigh.Status = finding.StatusNew
	okRun := []finding.ScannerRun{{Name: "opengrep", Category: finding.CategorySAST, Status: "ok"}}
	errRun := []finding.ScannerRun{{Name: "opengrep", Category: finding.CategorySAST, Status: "error", Error: "boom"}}
	tests := []struct {
		name   string
		event  string
		runs   []finding.ScannerRun
		fs     []finding.Finding
		policy string
		args   []string
		want   int
	}{
		{"clean passes", "push", okRun, nil, "", nil, 0},
		{"blocking fails", "push", okRun, []finding.Finding{high}, "", nil, 1},
		{"scanner error", "push", errRun, nil, "", nil, 2},
		{"scanner error in audit", "push", errRun, nil, "mode: audit\n", nil, 2},
		{"audit mode passes", "push", okRun, []finding.Finding{high}, "mode: audit\n", nil, 0},
		{"mode flag overrides file", "push", okRun, []finding.Finding{high}, "mode: audit\n", []string{"--mode", "enforce"}, 1},
		{"bad mode flag", "push", okRun, nil, "", []string{"--mode", "bogus"}, 2},
		{"pr ignores existing", "pr", okRun, []finding.Finding{high}, "mode: enforce\n", nil, 0},
		{"pr blocks new", "pr", okRun, []finding.Finding{newHigh}, "mode: enforce\n", nil, 1},
		{"invalid policy", "push", okRun, nil, "bogus: true\n", nil, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeGateFixture(t, dir, tt.event, tt.runs, tt.fs, tt.policy)
			var out, errb bytes.Buffer
			args := append([]string{"gate", "--dir", dir}, tt.args...)
			if code := run(args, envOf(nil), &out, &errb); code != tt.want {
				t.Fatalf("exit = %d, want %d, stderr = %s", code, tt.want, errb.String())
			}
			if tt.name == "bad mode flag" || tt.name == "invalid policy" {
				return
			}
			for _, f := range []string{"gate.env", "summary.md"} {
				if _, err := os.Stat(filepath.Join(dir, ".shipguard", f)); err != nil {
					t.Errorf("missing %s: %v", f, err)
				}
			}
			if !strings.Contains(out.String(), "shipguard") {
				t.Errorf("stdout = %q, want the summary", out.String())
			}
		})
	}
}

func TestGateMissingFindingsFailsClosed(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"gate", "--dir", t.TempDir()}, envOf(nil), &out, &errb); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "shipguard scan") {
		t.Errorf("stderr = %q, want a hint to run scan", errb.String())
	}
}

func TestGateFallsBackToRepoConfig(t *testing.T) {
	dir := t.TempDir()
	high := finding.Finding{ID: "R1", Category: finding.CategorySAST, Severity: finding.High, File: "a.go", Message: "bad"}
	writeGateFixture(t, dir, "push", okRunFixture, []finding.Finding{high}, "")
	cfg := filepath.Join(t.TempDir(), "custom.yaml")
	if err := os.WriteFile(cfg, []byte("mode: audit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"gate", "--dir", dir, "--config", cfg}, envOf(nil), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
}

func TestGateStepSummaryAndGitHubOutput(t *testing.T) {
	dir := t.TempDir()
	high := finding.Finding{ID: "R1", Category: finding.CategorySAST, Severity: finding.High, File: "a.go", Message: "bad"}
	writeGateFixture(t, dir, "push", okRunFixture, []finding.Finding{high}, "")
	tmp := t.TempDir()
	env := envOf(map[string]string{
		"GITHUB_STEP_SUMMARY": filepath.Join(tmp, "step.md"),
		"GITHUB_OUTPUT":       filepath.Join(tmp, "out.txt"),
	})
	var out, errb bytes.Buffer
	if code := run([]string{"gate", "--dir", dir}, env, &out, &errb); code != 1 {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	step, _ := os.ReadFile(filepath.Join(tmp, "step.md"))
	if !strings.Contains(string(step), "R1") {
		t.Errorf("step summary = %q", step)
	}
	o, _ := os.ReadFile(filepath.Join(tmp, "out.txt"))
	if !strings.Contains(string(o), "result=fail") {
		t.Errorf("GITHUB_OUTPUT = %q", o)
	}
}
