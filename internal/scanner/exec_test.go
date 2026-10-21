package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// reportFlags are the flags through which each scanner is told where to write
// its report.
var reportFlags = map[string]bool{"--output": true, "--output-file": true, "--report-path": true}

// fileRunner writes content (when non-nil) to the report flag of any scanner,
// records the report path and exits with code. git rev-parse is answered with
// <dir>/.git.
func fileRunner(t *testing.T, content []byte, code int, report *string) Runner {
	return func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
		if name == "git" {
			return []byte(filepath.Join(dir, ".git") + "\n"), nil, 0, nil
		}
		for i, a := range args {
			if reportFlags[a] && i+1 < len(args) {
				*report = args[i+1]
				if content != nil {
					if err := os.WriteFile(args[i+1], content, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		return nil, nil, code, nil
	}
}

var allScanners = map[string]func(Runner) Scanner{
	"gitleaks":      NewGitleaks,
	"opengrep":      func(r Runner) Scanner { return NewOpengrep(r, "/rules") },
	"osv":           NewOSV,
	"trivy-config":  NewTrivyConfig,
	"trivy-license": NewTrivyLicense,
}

// TestNullReportExitZeroIsEmpty: a literal null report from a scanner that
// exited 0 means no findings.
func TestNullReportExitZeroIsEmpty(t *testing.T) {
	noSleep(t)
	noTrivySleep(t)
	for name, mk := range allScanners {
		var report string
		fs, err := mk(fileRunner(t, []byte("null\n"), 0, &report)).Scan(context.Background(),
			Target{Dir: t.TempDir(), RawDir: t.TempDir(), CacheDir: t.TempDir()})
		if err != nil || len(fs) != 0 {
			t.Errorf("%s: fs=%v err=%v", name, fs, err)
		}
	}
}

// TestNullOrEmptyReportNonZeroExitIsError: opengrep and osv-scanner exit 1
// when they report findings, so a null or empty report with exit 1 means the
// report is missing, not that there is nothing to report.
func TestNullOrEmptyReportNonZeroExitIsError(t *testing.T) {
	noSleep(t)
	for _, name := range []string{"opengrep", "osv"} {
		for label, content := range map[string][]byte{"null": []byte("null"), "spaced null": []byte(" null \n"), "empty": {}, "blank": []byte("\n"), "missing": nil} {
			var report string
			fs, err := allScanners[name](fileRunner(t, content, 1, &report)).Scan(context.Background(),
				Target{Dir: t.TempDir(), RawDir: t.TempDir()})
			if err == nil {
				t.Errorf("%s exit 1 with %s report: want error, got fs=%v", name, label, fs)
			}
		}
	}
}

// TestEmptyReportExitZeroIsError: an empty report file means the scanner
// never wrote it (shipguard pre-creates it), so the scan did not run.
func TestEmptyReportExitZeroIsError(t *testing.T) {
	noSleep(t)
	noTrivySleep(t)
	for name, mk := range allScanners {
		for label, content := range map[string][]byte{"empty": {}, "missing": nil} {
			var report string
			if _, err := mk(fileRunner(t, content, 0, &report)).Scan(context.Background(),
				Target{Dir: t.TempDir(), RawDir: t.TempDir(), CacheDir: t.TempDir()}); err == nil {
				t.Errorf("%s exit 0 with %s report: want error", name, label)
			}
		}
	}
}

// TestTempReportRemovedOnError: the verbatim report (it can hold secrets or
// source lines) is deleted when the scan fails, both on a bad exit code and on
// an unparsable report.
func TestTempReportRemovedOnError(t *testing.T) {
	noSleep(t)
	noTrivySleep(t)
	for name, mk := range allScanners {
		for label, code := range map[string]int{"bad exit": 2, "bad report": 0} {
			var report string
			if _, err := mk(fileRunner(t, []byte("not json"), code, &report)).Scan(context.Background(),
				Target{Dir: t.TempDir(), RawDir: t.TempDir(), CacheDir: t.TempDir()}); err == nil {
				t.Fatalf("%s %s: want error", name, label)
			}
			if report == "" {
				t.Fatalf("%s %s: report path not seen", name, label)
			}
			if _, err := os.Stat(report); !os.IsNotExist(err) {
				t.Errorf("%s %s: temp report %s left behind (err=%v)", name, label, report, err)
			}
		}
	}
}

// TestOpengrepWithoutRawDir: an empty RawDir writes no raw copy anywhere, still
// returns the findings and removes the temp report.
func TestOpengrepWithoutRawDir(t *testing.T) {
	dir := t.TempDir()
	var report string
	fs, err := NewOpengrep(fileRunner(t, ogGolden(t, "results.json"), 1, &report), "/rules").Scan(context.Background(), Target{Dir: dir})
	if err != nil || len(fs) != 3 {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("Dir not left untouched: %v", entries)
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Errorf("temp report %s left behind (err=%v)", report, err)
	}
}
