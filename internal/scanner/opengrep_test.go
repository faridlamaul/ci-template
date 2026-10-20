package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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
		"--exclude-rule", "r.one", "--exclude-rule", "r.two",
		"--exclude", "vendor", "--exclude", "*.gen.go", ".",
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
