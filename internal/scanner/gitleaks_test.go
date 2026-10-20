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

// reportRunner writes golden to the --report-path argument.
func reportRunner(t *testing.T, golden []byte, argsOut *[]string, reportOut *string) Runner {
	return func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
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
		head []string
	}{
		{"pr range", Target{LogOpts: "base..head"}, []string{"git", "--log-opts=base..head"}},
		{"full history", Target{FullHistory: true}, []string{"git"}},
		{"dir", Target{}, []string{"dir", "."}},
		{"log opts wins", Target{LogOpts: "a..b", FullHistory: true}, []string{"git", "--log-opts=a..b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var args []string
			tc.tgt.Dir = t.TempDir()
			s := NewGitleaks(reportRunner(t, golden(t, "empty.json"), &args, nil))
			if _, err := s.Scan(context.Background(), tc.tgt); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(args[:len(tc.head)], tc.head) {
				t.Fatalf("args = %v, want prefix %v", args, tc.head)
			}
			tail := args[len(tc.head):]
			want := []string{"--report-format", "json", "--report-path", tail[3], "--exit-code", "0", "--no-banner"}
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
