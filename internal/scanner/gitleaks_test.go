package scanner

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// fakeSecret is the throwaway value embedded in the golden files.
const fakeSecret = "f9b00f23faf0ba1244389a00d791e0d8"

func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "gitleaks", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// reportRunner writes golden to the --report-path argument and answers
// `git rev-parse --absolute-git-dir` with <dir>/.git.
func reportRunner(t *testing.T, golden []byte, argsOut *[]string, reportOut *string) Runner {
	return func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
		if name == "git" {
			return []byte(filepath.Join(dir, ".git") + "\n"), nil, 0, nil
		}
		if argsOut != nil {
			*argsOut = args
		}
		for i, a := range args {
			if a == "--report-path" {
				if reportOut != nil {
					*reportOut = args[i+1]
				}
				if err := os.WriteFile(args[i+1], golden, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return nil, nil, 0, nil
	}
}

func TestParseGitleaks(t *testing.T) {
	for _, name := range []string{"git.json", "dir.json"} {
		fs, err := ParseGitleaks(golden(t, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 1 {
			t.Fatalf("%s: got %d findings", name, len(fs))
		}
		f := fs[0]
		if f.ID != "generic-api-key" || f.File != "src/config.go" || f.Line != 3 ||
			f.Scanner != "gitleaks" || f.Category != finding.CategorySecrets || f.Severity != finding.High ||
			f.Message == "" || f.Fingerprint != finding.Fingerprint("generic-api-key", "src/config.go", finding.SecretKey(fakeSecret)) {
			t.Fatalf("%s: unexpected finding %+v", name, f)
		}
		if strings.Contains(strings.ReplaceAll(strings.Join([]string{f.ID, f.File, f.Message, f.Fingerprint, f.Package, f.Version}, "|"), "\n", ""), fakeSecret) {
			t.Fatalf("%s: secret leaked into finding", name)
		}
	}
	if fs, err := ParseGitleaks(golden(t, "empty.json")); err != nil || len(fs) != 0 {
		t.Fatalf("empty: %v %v", fs, err)
	}
	if _, err := ParseGitleaks([]byte("not json")); err == nil {
		t.Fatal("want parse error")
	}
}

func TestGitleaksStripsAbsolutePrefix(t *testing.T) {
	dir := filepath.Join(string(filepath.Separator), "repo")
	rawDir := t.TempDir()
	s := NewGitleaks(reportRunner(t, golden(t, "dir-absolute.json"), nil, nil))
	fs, err := s.Scan(context.Background(), Target{Dir: dir, RawDir: rawDir})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].File != "src/config.go" {
		t.Fatalf("got %+v", fs)
	}
}

func TestGitleaksRawHasNoSecret(t *testing.T) {
	rawDir := filepath.Join(t.TempDir(), "raw")
	dir := t.TempDir()
	var report string
	s := NewGitleaks(reportRunner(t, golden(t, "git.json"), nil, &report))
	found, err := s.Scan(context.Background(), Target{Dir: dir, RawDir: rawDir})
	if err != nil || len(found) != 1 {
		t.Fatalf("scan: %v %v", found, err)
	}
	if report == "" {
		t.Fatal("runner never saw a report path")
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatalf("temporary report not deleted: %v", err)
	}
	if within(dir, report) || within(rawDir, report) {
		t.Fatalf("report %s is inside Dir or RawDir", report)
	}
	raw, err := os.ReadFile(filepath.Join(rawDir, "gitleaks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "generic-api-key") {
		t.Fatalf("raw copy missing findings: %s", raw)
	}
	for _, root := range []string{rawDir, dir} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				b, _ := os.ReadFile(p)
				if strings.Contains(string(b), fakeSecret) {
					t.Errorf("secret found in %s", p)
				}
			}
			return nil
		})
	}
}

func TestGitleaksArgs(t *testing.T) {
	tests := []struct {
		name string
		tgt  Target
		head []string // before the source path
		git  bool     // source is the git dir, not the work tree
	}{
		{"pr range", Target{LogOpts: "base..head"}, []string{"git", "--log-opts=base..head"}, true},
		{"full history", Target{FullHistory: true}, []string{"git"}, true},
		{"dir", Target{}, []string{"dir"}, false},
		{"log opts wins", Target{LogOpts: "a..b", FullHistory: true}, []string{"git", "--log-opts=a..b"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			var resolved string
			var resolveErr error
			tc.tgt.Dir = t.TempDir()
			inner := reportRunner(t, golden(t, "empty.json"), &args, nil)
			run := func(ctx context.Context, dir, name string, a ...string) ([]byte, []byte, int, error) {
				if name == "gitleaks" && a[0] == "dir" {
					resolved, resolveErr = filepath.EvalSymlinks(a[1])
				}
				return inner(ctx, dir, name, a...)
			}
			s := NewGitleaks(run)
			if _, err := s.Scan(context.Background(), tc.tgt); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(args[:len(tc.head)], tc.head) {
				t.Fatalf("args = %v, want prefix %v", args, tc.head)
			}
			src := args[len(tc.head)]
			if tc.git {
				if src != filepath.Join(tc.tgt.Dir, ".git") {
					t.Fatalf("source = %q, want the git dir", src)
				}
			} else {
				// A random symlink to the work tree, so fingerprints in a
				// committed .gitleaksignore can never match.
				if !strings.HasSuffix(src, string(filepath.Separator)) || within(tc.tgt.Dir, src) {
					t.Fatalf("source = %q, want a trailing-separator path outside Dir", src)
				}
				if resolveErr != nil || !sameDir(t, resolved, tc.tgt.Dir) {
					t.Fatalf("source %q resolves to %q (%v), want %s", src, resolved, resolveErr, tc.tgt.Dir)
				}
				if _, err := os.Lstat(strings.TrimSuffix(src, string(filepath.Separator))); !os.IsNotExist(err) {
					t.Fatalf("source link %s not removed: %v", src, err)
				}
			}
			tail := args[len(tc.head)+1:]
			want := []string{"--report-format", "json", "--report-path", tail[3], "--exit-code", "0", "--no-banner",
				"--config", tail[8], "--gitleaks-ignore-path", tail[10], "--ignore-gitleaks-allow"}
			if !reflect.DeepEqual(tail, want) {
				t.Fatalf("tail = %v", tail)
			}
			for _, a := range args {
				if a == "--redact" {
					t.Fatal("must not redact")
				}
			}
		})
	}
}

func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}

// TestGitleaksNeutralizesRepoControls checks that the repository cannot tune
// gitleaks: the config is the built-in default only, the ignore path
// is an empty directory outside the repository, and gitleaks:allow comments
// are ignored.
func TestGitleaksNeutralizesRepoControls(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		".gitleaks.toml":  "[extend]\nuseDefault = false\n",
		".gitleaksignore": "src/config.go:generic-api-key:3\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var cfg, ignDir string
	var ignEntries []os.DirEntry
	run := func(ctx context.Context, d, name string, args ...string) ([]byte, []byte, int, error) {
		if name == "git" {
			return []byte(filepath.Join(d, ".git")), nil, 0, nil
		}
		cfg = argAfter(args, "--config")
		ignDir = argAfter(args, "--gitleaks-ignore-path")
		b, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		if string(b) != "[extend]\nuseDefault = true\n" {
			t.Fatalf("config = %q, want the built-in defaults only", b)
		}
		if ignEntries, err = os.ReadDir(ignDir); err != nil {
			t.Fatalf("ignore path: %v", err)
		}
		if !contains(args, "--ignore-gitleaks-allow") {
			t.Fatalf("args %v lack --ignore-gitleaks-allow", args)
		}
		if err := os.WriteFile(argAfter(args, "--report-path"), golden(t, "empty.json"), 0o600); err != nil {
			t.Fatal(err)
		}
		return nil, nil, 0, nil
	}
	for _, tgt := range []Target{{Dir: dir}, {Dir: dir, LogOpts: "a..b"}, {Dir: dir, FullHistory: true}} {
		if _, err := NewGitleaks(run).Scan(context.Background(), tgt); err != nil {
			t.Fatal(err)
		}
		if within(dir, cfg) || within(dir, ignDir) {
			t.Fatalf("config %s or ignore dir %s is inside the repository", cfg, ignDir)
		}
		if len(ignEntries) != 0 {
			t.Fatalf("ignore dir has %d entries, want none", len(ignEntries))
		}
		if _, err := os.Stat(cfg); !os.IsNotExist(err) {
			t.Fatalf("temp config %s not removed: %v", cfg, err)
		}
	}
}

func TestGitleaksDirStripsSourceLinkPrefix(t *testing.T) {
	dir := t.TempDir()
	run := func(ctx context.Context, d, name string, args ...string) ([]byte, []byte, int, error) {
		src := args[1] // dir <source>
		report := strings.ReplaceAll(string(golden(t, "dir-absolute.json")), "/repo/", filepath.ToSlash(src))
		if err := os.WriteFile(argAfter(args, "--report-path"), []byte(report), 0o600); err != nil {
			t.Fatal(err)
		}
		return nil, nil, 0, nil
	}
	fs, err := NewGitleaks(run).Scan(context.Background(), Target{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].File != "src/config.go" {
		t.Fatalf("got %+v", fs)
	}
}

func TestGitleaksGitDirErrorIsError(t *testing.T) {
	run := func(ctx context.Context, d, name string, args ...string) ([]byte, []byte, int, error) {
		if name == "git" {
			return nil, []byte("fatal: not a git repository"), 128, nil
		}
		t.Fatal("gitleaks must not run without a git dir")
		return nil, nil, 0, nil
	}
	if _, err := NewGitleaks(run).Scan(context.Background(), Target{Dir: t.TempDir(), LogOpts: "a..b"}); err == nil {
		t.Fatal("want error")
	}
}

func TestGitleaksNonZeroExitIsError(t *testing.T) {
	s := NewGitleaks(func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
		return nil, []byte("boom"), 1, nil
	})
	if _, err := s.Scan(context.Background(), Target{Dir: t.TempDir()}); err == nil {
		t.Fatal("want error on exit 1")
	}
}

func TestRetryBackoff(t *testing.T) {
	var sleeps []time.Duration
	last := errors.New("third")
	errs := []error{errors.New("first"), errors.New("second"), last}
	i := 0
	err := Retry(context.Background(), 3, func(d time.Duration) { sleeps = append(sleeps, d) }, func() error {
		e := errs[i]
		i++
		return e
	})
	if err != last {
		t.Fatalf("err = %v", err)
	}
	if !reflect.DeepEqual(sleeps, []time.Duration{time.Second, 2 * time.Second}) {
		t.Fatalf("sleeps = %v", sleeps)
	}
	// success short-circuits; fourth attempt backs off 4s.
	sleeps = nil
	n := 0
	err = Retry(context.Background(), 4, func(d time.Duration) { sleeps = append(sleeps, d) }, func() error {
		n++
		if n < 4 {
			return errors.New("x")
		}
		return nil
	})
	if err != nil || !reflect.DeepEqual(sleeps, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Fatalf("err=%v sleeps=%v", err, sleeps)
	}
}

func TestRetryStopsWhenContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	boom := errors.New("boom")
	err := Retry(ctx, 5, func(time.Duration) { t.Fatal("must not sleep") }, func() error {
		calls++
		cancel()
		return boom
	})
	if err != boom || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestScanTimeoutIsError(t *testing.T) {
	blocking := func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
		<-ctx.Done()
		return nil, nil, -1, ctx.Err()
	}
	got, err := NewGitleaks(blocking).Scan(context.Background(), Target{Dir: t.TempDir(), Timeout: 20 * time.Millisecond})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || got != nil {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestExecRunner(t *testing.T) {
	run := ExecRunner()
	out, _, code, err := run(context.Background(), t.TempDir(), "sh", "-c", "echo hi; exit 3")
	if err != nil || code != 3 || strings.TrimSpace(string(out)) != "hi" {
		t.Fatalf("out=%q code=%d err=%v", out, code, err)
	}
	if _, _, _, err := run(context.Background(), t.TempDir(), "shipguard-no-such-binary"); err == nil {
		t.Fatal("want start error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, _, err := run(ctx, t.TempDir(), "sleep", "5"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestRetryNonPositiveAttemptsCallsOnce(t *testing.T) {
	for _, n := range []int{0, -3} {
		calls := 0
		err := Retry(context.Background(), n, func(time.Duration) { t.Fatal("must not sleep") }, func() error {
			calls++
			return errors.New("boom")
		})
		if calls != 1 || err == nil {
			t.Fatalf("attempts=%d: calls=%d err=%v", n, calls, err)
		}
	}
}

func TestRetryStopsWhenContextDoneDuringSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := Retry(ctx, 5, func(time.Duration) { cancel() }, func() error {
		calls++
		return errors.New("boom")
	})
	if calls != 1 || err == nil {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
