package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/faridlamaul/shipguard/internal/finding"
)

func ogGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "opengrep", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// outputRunner writes golden to the --output argument and returns exit code.
func outputRunner(t *testing.T, golden []byte, code int, argsOut *[]string) Runner {
	return func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
		if argsOut != nil {
			*argsOut = args
		}
		for i, a := range args {
			if a == "--output" && golden != nil {
				if err := os.WriteFile(args[i+1], golden, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return nil, nil, code, nil
	}
}

func TestParseOpengrepSeverityMap(t *testing.T) {
	fs, err := ParseOpengrep(ogGolden(t, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]finding.Severity{}
	for _, f := range fs {
		got[f.ID] = f.Severity
		if f.Scanner != "opengrep" || f.Category != finding.CategorySAST || f.File != "app.py" || f.Line == 0 || f.Message == "" || f.Fingerprint == "" {
			t.Fatalf("unexpected finding %+v", f)
		}
	}
	want := map[string]finding.Severity{
		"test.no-eval": finding.High, "test.no-os-system": finding.Medium, "test.no-print": finding.Low,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, f := range fs {
		if f.ID == "test.no-eval" {
			if f.Line != 3 || f.Message != "Do not use eval" ||
				f.Fingerprint != finding.Fingerprint("test.no-eval", "app.py", finding.NormalizeSnippet("    eval(x)")) {
				t.Fatalf("eval finding %+v", f)
			}
		}
	}
	if fs, err := ParseOpengrep(ogGolden(t, "empty.json")); err != nil || len(fs) != 0 {
		t.Fatalf("empty: %v %v", fs, err)
	}
	if _, err := ParseOpengrep([]byte("not json")); err == nil {
		t.Fatal("want parse error")
	}
	if _, err := ParseOpengrep([]byte(`{"results":[{"check_id":"x","path":"a","start":{"line":1},"extra":{"severity":"WEIRD"}}]}`)); err == nil {
		t.Fatal("want unknown severity error")
	}
}

func TestOpengrepArgsIncludeConsumerRules(t *testing.T) {
	var args []string
	s := NewOpengrep(outputRunner(t, ogGolden(t, "empty.json"), 0, &args), "/opt/shipguard/rules")
	raw := t.TempDir()
	_, err := s.Scan(context.Background(), Target{
		Dir: t.TempDir(), RawDir: raw,
		Rules: []string{"rules/a.yml", "rules/b.yml"}, DisableRules: []string{"r.one", "r.two"},
		Exclude: []string{"vendor", "*.gen.go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(args) < 4 {
		t.Fatalf("args = %v", args)
	}
	want := []string{
		"scan", "--json", "--output", args[3],
		"--config", "/opt/shipguard/rules", "--config", "rules/a.yml", "--config", "rules/b.yml",
		"--exclude", "vendor", "--exclude", "*.gen.go",
		"--disable-nosem", "--x-ignore-semgrepignore-files", ".",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %v\nwant   %v", args, want)
	}
}

func TestOpengrepFatalErrorsAreErrors(t *testing.T) {
	s := NewOpengrep(outputRunner(t, ogGolden(t, "fatal-error.json"), 0, nil), "/rules")
	_, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "Rule parse error") || strings.Contains(err.Error(), "foo(") {
		t.Fatalf("want fatal error, got %v", err)
	}
	if _, err := ParseOpengrep(ogGolden(t, "fatal-error.json")); err == nil {
		t.Fatal("ParseOpengrep must report level=error entries")
	}
}

func TestOpengrepWarnErrorsAreIgnored(t *testing.T) {
	s := NewOpengrep(outputRunner(t, ogGolden(t, "warn-error.json"), 0, nil), "/rules")
	fs, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()})
	if err != nil || len(fs) != 0 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
}

func TestOpengrepExitCodes(t *testing.T) {
	for _, code := range []int{0, 1} {
		s := NewOpengrep(outputRunner(t, ogGolden(t, "results.json"), code, nil), "/rules")
		fs, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()})
		if err != nil || len(fs) != 3 {
			t.Fatalf("code %d: %v %v", code, fs, err)
		}
	}
	s := NewOpengrep(outputRunner(t, ogGolden(t, "results.json"), 2, nil), "/rules")
	if _, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()}); err == nil {
		t.Fatal("want error on exit 2")
	}
}

func TestOpengrepEmptyOrInvalidOutputIsError(t *testing.T) {
	for name, g := range map[string][]byte{"empty": {}, "garbage": []byte("nope"), "missing": nil} {
		s := NewOpengrep(outputRunner(t, g, 0, nil), "/rules")
		if _, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()}); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}

func TestOpengrepErrorOmitsStderr(t *testing.T) {
	s := NewOpengrep(func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
		return nil, []byte("password = hunter2"), 2, nil
	}, "/rules")
	_, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()})
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpengrepNormalizesPaths(t *testing.T) {
	dir := filepath.Join(string(filepath.Separator), "repo")
	raw := `{"results":[{"check_id":"r","path":"` + filepath.ToSlash(filepath.Join(dir, "src", "a.py")) +
		`","start":{"line":2},"extra":{"message":"m","severity":"ERROR","lines":" x  = 1"}}],"errors":[]}`
	fs, err := parseOpengrep([]byte(raw), dir)
	if err != nil || len(fs) != 1 || fs[0].File != "src/a.py" {
		t.Fatalf("fs=%+v err=%v", fs, err)
	}
}

func TestOpengrepRawHasNoSourceLines(t *testing.T) {
	raw := filepath.Join(t.TempDir(), "raw")
	dir := t.TempDir()
	var args []string
	s := NewOpengrep(outputRunner(t, ogGolden(t, "results.json"), 1, &args), "/rules")
	if _, err := s.Scan(context.Background(), Target{Dir: dir, RawDir: raw}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(raw, "opengrep.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "test.no-eval") || strings.Contains(string(b), "eval(x)") {
		t.Fatalf("raw copy wrong: %s", b)
	}
	out := args[3]
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("temporary output not deleted: %v", err)
	}
	if within(dir, out) || within(raw, out) {
		t.Fatalf("output %s is inside Dir or RawDir", out)
	}
}

// prefixed.json is real `opengrep scan --config <dir>` output (v1.31.0): the
// check_id carries the dotted config directory path before the rule id.
func TestOpengrepStripsConfigPrefixFromCheckID(t *testing.T) {
	rules := t.TempDir()
	rule := "rules:\n  - id: shipguard.python.unsafe-deserialization\n    languages: [python]\n    severity: ERROR\n    message: m\n    pattern: pickle.loads(...)\n"
	if err := os.WriteFile(filepath.Join(rules, "r.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewOpengrep(outputRunner(t, ogGolden(t, "prefixed.json"), 1, nil), rules)
	fs, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()})
	if err != nil || len(fs) != 1 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	if fs[0].ID != "shipguard.python.unsafe-deserialization" {
		t.Fatalf("id = %q", fs[0].ID)
	}
	// Fallback without readable rule files: cut to the shipguard. segment.
	s = NewOpengrep(outputRunner(t, ogGolden(t, "prefixed.json"), 1, nil), "/nonexistent")
	fs, err = s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()})
	if err != nil || len(fs) != 1 || fs[0].ID != "shipguard.python.unsafe-deserialization" {
		t.Fatalf("fallback: fs=%v err=%v", fs, err)
	}
}

func TestOpengrepDisableRulesUseBareIDs(t *testing.T) {
	var args []string
	s := NewOpengrep(outputRunner(t, ogGolden(t, "prefixed.json"), 1, &args), "/nonexistent")
	fs, err := s.Scan(context.Background(), Target{
		Dir: t.TempDir(), RawDir: t.TempDir(),
		DisableRules: []string{"shipguard.python.unsafe-deserialization"},
	})
	if err != nil || len(fs) != 0 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	for _, a := range args {
		if a == "--exclude-rule" {
			t.Fatalf("--exclude-rule must not be passed: %v", args)
		}
	}
}

func TestNormalizeCheckIDConsumerRules(t *testing.T) {
	known := []string{"team.no-eval", "no-eval"}
	for in, want := range map[string]string{
		"rules.team.no-eval":                       "team.no-eval",
		"a.b.rules.sub.no-eval":                    "no-eval",
		"opt.shipguard.rules.go.shipguard.go.ssrf": "shipguard.go.ssrf",
		"plain": "plain",
	} {
		if got := normalizeCheckID(in, known); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}

func TestOpengrepDefaultExcludes(t *testing.T) {
	for _, on := range []bool{true, false} {
		var args []string
		s := NewOpengrep(outputRunner(t, ogGolden(t, "empty.json"), 0, &args), "/opt/shipguard/rules")
		_, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir(), Exclude: []string{"docs/"}, SASTDefaultExcludes: on})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for i, a := range args {
			if a == "--exclude" {
				got = append(got, args[i+1])
			}
		}
		want := []string{"docs/"}
		if on {
			want = append(want, OpengrepDefaultExcludes()...)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("default_excludes=%v: --exclude = %v, want %v", on, got, want)
		}
	}
	for _, p := range []string{"vendor/", "build/", "dist/", ".venv/", ".tox/", ".npm/", ".yarn/", "*.min.js", "test/", "tests/", "*_test.go"} {
		if !slices.Contains(OpengrepDefaultExcludes(), p) {
			t.Errorf("OpengrepDefaultExcludes lacks %q", p)
		}
	}
	OpengrepDefaultExcludes()[0] = "changed"
	if OpengrepDefaultExcludes()[0] == "changed" {
		t.Error("accessor must return a copy")
	}
}
