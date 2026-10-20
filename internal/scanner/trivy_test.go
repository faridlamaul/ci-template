package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
)

func trivyGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "trivy", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noTrivySleep(t *testing.T) {
	t.Helper()
	old := trivySleep
	trivySleep = func(time.Duration) {}
	t.Cleanup(func() { trivySleep = old })
}

func TestParseTrivyConfigOnlyFailures(t *testing.T) {
	fs, err := ParseTrivyConfig(trivyGolden(t, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 5 {
		t.Fatalf("want 5 findings, got %d: %+v", len(fs), fs)
	}
	byID := map[string]finding.Finding{}
	for _, f := range fs {
		byID[f.ID] = f
	}
	d := byID["DS-0002"]
	if d.ID != "DS-0002" || d.File != "Dockerfile" || d.Line != 0 || d.Severity != finding.High ||
		d.Scanner != "trivy-config" || d.Category != finding.CategoryIaC || d.Message == "" ||
		d.Fingerprint != finding.Fingerprint("DS-0002", "Dockerfile", "Image user should not be 'root'") {
		t.Fatalf("dockerfile finding %+v", d)
	}
	if k := byID["KSV-0001"]; k.ID != "KSV-0001" || k.File != "k8s/pod.yaml" || k.Line != 7 || k.Severity != finding.Medium {
		t.Fatalf("k8s finding %+v", k)
	}

	raw := `{"Results":[{"Target":"a.yaml","Misconfigurations":[
	 {"ID":"KSV-1","AVDID":"AVD-KSV-0001","Title":"T  one","Severity":"CRITICAL","Status":"FAIL","CauseMetadata":{"Resource":"Pod/x","StartLine":4}},
	 {"ID":"KSV-2","Title":"ok","Severity":"HIGH","Status":"PASS"},
	 {"ID":"KSV-3","Title":"skipped","Severity":"HIGH","Status":"EXCEPTION"}]},
	 {"Target":"b.yaml"}]}`
	fs, err = ParseTrivyConfig([]byte(raw))
	if err != nil || len(fs) != 1 {
		t.Fatalf("%v %v", fs, err)
	}
	f := fs[0]
	if f.ID != "AVD-KSV-0001" || f.Severity != finding.Critical || f.Line != 4 ||
		f.Fingerprint != finding.Fingerprint("AVD-KSV-0001", "a.yaml", "Pod/x") {
		t.Fatalf("got %+v", f)
	}
}

func TestParseTrivyLicenseDeny(t *testing.T) {
	fs, err := ParseTrivyLicense(trivyGolden(t, "license.json"), []string{"AGPL-3.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %+v", fs)
	}
	byPkg := map[string]finding.Finding{}
	for _, f := range fs {
		byPkg[f.Package] = f
	}
	a, m := byPkg["agpl-pkg"], byPkg["left-pad"]
	if a.Severity != finding.High || a.ID != "license:AGPL-3.0-only" || a.File != "package-lock.json" ||
		a.Scanner != "trivy-license" || a.Category != finding.CategorySCA || a.Fingerprint == "" {
		t.Fatalf("agpl %+v", a)
	}
	if m.Severity != finding.Info || m.ID != "license:MIT" {
		t.Fatalf("mit %+v", m)
	}
	fs, err = ParseTrivyLicense(trivyGolden(t, "license.json"), nil)
	if err != nil || len(fs) != 2 || fs[0].Severity != finding.Info || fs[1].Severity != finding.Info {
		t.Fatalf("no deny: %+v %v", fs, err)
	}
	// Exact SPDX ids and case-insensitive matches also deny.
	fs, _ = ParseTrivyLicense(trivyGolden(t, "license.json"), []string{"mit"})
	for _, f := range fs {
		if (f.Package == "left-pad") != (f.Severity == finding.High) {
			t.Fatalf("case-insensitive deny: %+v", f)
		}
	}
	// A deny entry covers the whole family: GPL-3.0 denies -or-later and +.
	fam := `{"Results":[{"Target":"l","Licenses":[{"PkgName":"a","Name":"GPL-3.0-or-later"},{"PkgName":"b","Name":"GPL-3.0+"},{"PkgName":"c","Name":"LGPL-3.0"}]}]}`
	fs, err = ParseTrivyLicense([]byte(fam), []string{"GPL-3.0"})
	if err != nil || len(fs) != 3 || fs[0].Severity != finding.High || fs[1].Severity != finding.High || fs[2].Severity != finding.Info {
		t.Fatalf("family deny: %+v %v", fs, err)
	}
}

func TestParseTrivyErrors(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte("not json")} {
		if _, err := ParseTrivyConfig(bad); err == nil {
			t.Fatalf("config %q: want error", bad)
		}
		if _, err := ParseTrivyLicense(bad, nil); err == nil {
			t.Fatalf("license %q: want error", bad)
		}
	}
	if fs, err := ParseTrivyConfig([]byte(`{"Results":null}`)); err != nil || len(fs) != 0 {
		t.Fatalf("%v %v", fs, err)
	}
}

type trivyCall struct {
	name string
	args []string
}

// trivyRunner fakes trivy: scans write golden to --output and exit scanCode.
func trivyRunner(t *testing.T, golden []byte, scanCode int, calls *[]trivyCall) Runner {
	return func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
		*calls = append(*calls, trivyCall{name, append([]string(nil), args...)})
		for i, a := range args {
			if a == "--output" && golden != nil {
				if err := os.WriteFile(args[i+1], golden, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return nil, []byte("SECRET-STDERR"), scanCode, nil
	}
}

func TestTrivyConfigRetriesThenErrors(t *testing.T) {
	noTrivySleep(t)
	var calls []trivyCall
	s := NewTrivyConfig(trivyRunner(t, nil, 1, &calls))
	_, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir(), CacheDir: t.TempDir()})
	if err == nil || len(calls) != 3 {
		t.Fatalf("err=%v calls=%d (want 3 attempts then error)", err, len(calls))
	}
	if strings.Contains(err.Error(), "SECRET-STDERR") {
		t.Fatalf("stderr leaked: %v", err)
	}
	// Runner errors are retried too.
	n := 0
	_, err = NewTrivyConfig(func(context.Context, string, string, ...string) ([]byte, []byte, int, error) {
		n++
		return nil, nil, -1, errors.New("boom")
	}).Scan(context.Background(), Target{Dir: t.TempDir(), CacheDir: t.TempDir()})
	if err == nil || n != 3 {
		t.Fatalf("runner error: err=%v n=%d", err, n)
	}
}

func TestTrivyLicenseNoRetry(t *testing.T) {
	noTrivySleep(t)
	var calls []trivyCall
	_, err := NewTrivyLicense(trivyRunner(t, nil, 1, &calls)).Scan(context.Background(), Target{Dir: t.TempDir(), CacheDir: t.TempDir()})
	if err == nil || len(calls) != 1 {
		t.Fatalf("err=%v calls=%d (want 1)", err, len(calls))
	}
}

func TestTrivyChecksBundleEnv(t *testing.T) {
	noTrivySleep(t)
	var calls []trivyCall
	tgt := func() Target { return Target{Dir: t.TempDir(), RawDir: t.TempDir(), CacheDir: t.TempDir()} }
	s := NewTrivyConfig(trivyRunner(t, trivyGolden(t, "config.json"), 0, &calls))
	if _, err := s.Scan(context.Background(), tgt()); err != nil || contains(calls[0].args, "--checks-bundle-repository") {
		t.Fatalf("unset: %v %v", err, calls[0].args)
	}
	t.Setenv("SHIPGUARD_TRIVY_CHECKS_BUNDLE_REPOSITORY", "registry.example/checks:2")
	calls = nil
	if _, err := s.Scan(context.Background(), tgt()); err != nil {
		t.Fatal(err)
	}
	if got := argAfter(calls[0].args, "--checks-bundle-repository"); got != "registry.example/checks:2" {
		t.Fatalf("args %v", calls[0].args)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func TestTrivyConfigScan(t *testing.T) {
	noTrivySleep(t)
	raw, cache := t.TempDir(), t.TempDir()
	var calls []trivyCall
	s := NewTrivyConfig(trivyRunner(t, trivyGolden(t, "config.json"), 0, &calls))
	if s.Name() != "trivy-config" || s.Category() != finding.CategoryIaC {
		t.Fatalf("%s %s", s.Name(), s.Category())
	}
	fs, err := s.Scan(context.Background(), Target{Dir: "/src", RawDir: raw, CacheDir: cache,
		Exclude: []string{".shipguard/", "node_modules/", "**/*.gen.yaml", "vendor/"}})
	if err != nil || len(fs) != 5 {
		t.Fatalf("fs=%d err=%v", len(fs), err)
	}
	scan := calls[len(calls)-1]
	out := argAfter(scan.args, "--output")
	if scan.name != "trivy" || scan.args[0] != "config" || out == "" || strings.HasPrefix(out, raw) {
		t.Fatalf("scan call %+v", scan)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("temp report not removed: %v", err)
	}
	want := []string{"config", "--format", "json", "--output", out, "--cache-dir", filepath.Join(cache, "trivy"),
		"--config", "", "--ignorefile", "",
		"--skip-dirs", ".shipguard", "--skip-dirs", "node_modules", "--skip-dirs", "vendor", "--exit-code", "0", "."}
	if !reflect.DeepEqual(scan.args, want) {
		t.Fatalf("args\n got %v\nwant %v", scan.args, want)
	}
	b, err := os.ReadFile(filepath.Join(raw, "trivy-config.json"))
	var back []finding.Finding
	if err != nil || json.Unmarshal(b, &back) != nil || !reflect.DeepEqual(back, fs) {
		t.Fatalf("raw %v: %v", err, string(b))
	}
}

func TestTrivyLicenseScan(t *testing.T) {
	noTrivySleep(t)
	raw, cache := t.TempDir(), t.TempDir()
	var calls []trivyCall
	s := NewTrivyLicense(trivyRunner(t, trivyGolden(t, "license.json"), 0, &calls))
	if s.Name() != "trivy-license" || s.Category() != finding.CategorySCA {
		t.Fatalf("%s %s", s.Name(), s.Category())
	}
	fs, err := s.Scan(context.Background(), Target{Dir: "/src", RawDir: raw, CacheDir: cache, DenyLicenses: []string{"AGPL-3.0"},
		Exclude: []string{"vendor/", "**/*.gen"}})
	if err != nil || len(fs) != 2 {
		t.Fatalf("fs=%d err=%v", len(fs), err)
	}
	scan := calls[len(calls)-1]
	out := argAfter(scan.args, "--output")
	want := []string{"fs", "--scanners", "license", "--format", "json", "--output", out, "--cache-dir", filepath.Join(cache, "trivy"),
		"--skip-db-update", "--config", "", "--ignorefile", "", "--skip-dirs", "vendor", "--exit-code", "0", "."}
	if !reflect.DeepEqual(scan.args, want) {
		t.Fatalf("args\n got %v\nwant %v", scan.args, want)
	}
	for _, f := range fs {
		if (f.Package == "agpl-pkg") != (f.Severity == finding.High) {
			t.Fatalf("deny not applied: %+v", f)
		}
	}
	if _, err := os.Stat(filepath.Join(raw, "trivy-license.json")); err != nil {
		t.Fatal(err)
	}
}

func TestTrivyScanErrors(t *testing.T) {
	noTrivySleep(t)
	tgt := func() Target { return Target{Dir: t.TempDir(), RawDir: t.TempDir(), CacheDir: t.TempDir()} }
	var calls []trivyCall
	// Non-zero exit is an error, without leaking stderr.
	_, err := NewTrivyConfig(trivyRunner(t, trivyGolden(t, "config.json"), 1, &calls)).Scan(context.Background(), tgt())
	if err == nil || strings.Contains(err.Error(), "SECRET-STDERR") {
		t.Fatalf("exit 1: %v", err)
	}
	// Empty output is an error.
	_, err = NewTrivyLicense(trivyRunner(t, nil, 0, &calls)).Scan(context.Background(), tgt())
	if err == nil {
		t.Fatal("missing output must error")
	}
	_, err = NewTrivyLicense(trivyRunner(t, []byte{}, 0, &calls)).Scan(context.Background(), tgt())
	if err == nil {
		t.Fatal("empty output must error")
	}
	// Runner failure.
	boom := errors.New("boom")
	_, err = NewTrivyConfig(func(context.Context, string, string, ...string) ([]byte, []byte, int, error) {
		return nil, nil, -1, boom
	}).Scan(context.Background(), tgt())
	if !errors.Is(err, boom) {
		t.Fatalf("want wrapped runner error, got %v", err)
	}
}

func TestTrivySkipDirsNestedGlobs(t *testing.T) {
	got := trivySkipDirs(Target{Exclude: []string{"node_modules/", "**/node_modules/**", "vendor/**", "**/*.gen.yaml", "**", "/"}})
	want := []string{"--skip-dirs", "node_modules", "--skip-dirs", "**/node_modules", "--skip-dirs", "vendor"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
