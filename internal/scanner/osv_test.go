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

func osvGolden(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "osv", "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noSleep(t *testing.T) {
	t.Helper()
	old := osvSleep
	osvSleep = func(time.Duration) {}
	t.Cleanup(func() { osvSleep = old })
}

func TestParseOSVFixAvailable(t *testing.T) {
	fs, err := parseOSV(osvGolden(t), "/src")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]finding.Finding{}
	for _, f := range fs {
		byID[f.ID] = f
		if f.Scanner != "osv-scanner" || f.Category != finding.CategorySCA || f.File != "requirements.txt" || f.Fingerprint == "" {
			t.Fatalf("unexpected finding %+v", f)
		}
	}
	if len(fs) != 6 {
		t.Fatalf("want 6 findings (package x vulnerability), got %d", len(fs))
	}
	fixed := byID["PYSEC-2018-66"]
	if fixed.Package != "flask" || fixed.Version != "0.12.2" || fixed.FixedVersion != "0.12.3" || !fixed.FixAvailable ||
		fixed.Severity != finding.High || !reflect.DeepEqual(fixed.Aliases, []string{"CVE-2018-1000656", "GHSA-562c-5r94-xh97"}) ||
		fixed.Fingerprint != finding.Fingerprint("PYSEC-2018-66", "requirements.txt", "flask@0.12.2") {
		t.Fatalf("fixed finding %+v", fixed)
	}
	unfixed := byID["GHSA-6528-wvf6-f6qg"]
	if unfixed.Package != "pycrypto" || unfixed.FixedVersion != "" || unfixed.FixAvailable || unfixed.Severity != finding.High {
		t.Fatalf("unfixed finding %+v", unfixed)
	}
	// A git-commit "fixed" event in a GIT range is not a fixed version.
	if g := byID["PYSEC-2017-94"]; g.FixedVersion != "" || g.FixAvailable || g.Severity != finding.Critical {
		t.Fatalf("git range finding %+v", g)
	}
}

func TestParseOSVErrors(t *testing.T) {
	if _, err := parseOSV([]byte("not json"), ""); err == nil {
		t.Fatal("want parse error")
	}
	if _, err := parseOSV(nil, ""); err == nil {
		t.Fatal("want error on empty output")
	}
	fs, err := parseOSV([]byte(`{"results":[]}`), "")
	if err != nil || len(fs) != 0 {
		t.Fatalf("empty results: %v %v", fs, err)
	}
	if _, err := ParseOSV(osvGolden(t)); err != nil {
		t.Fatal(err)
	}
}

func TestOSVSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		in   string
		want finding.Severity
	}{
		{"10.0", finding.Critical}, {"9.0", finding.Critical}, {"8.9", finding.High}, {"7.0", finding.High},
		{"6.9", finding.Medium}, {"4.0", finding.Medium}, {"3.9", finding.Low}, {"0.1", finding.Low},
		{"0", finding.Medium}, {"", finding.Medium}, {"high", finding.Medium}, {"-1", finding.Medium},
	}
	for _, c := range cases {
		if got := osvSeverity(c.in); got != c.want {
			t.Errorf("osvSeverity(%q) = %s want %s", c.in, got, c.want)
		}
	}
}

func TestOSVSeverityUsesGroupOfID(t *testing.T) {
	raw := `{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"Go"},
	"vulnerabilities":[{"id":"V1"},{"id":"V2"},{"id":"V3"}],
	"groups":[{"ids":["V1"],"max_severity":"9.5"},{"ids":["V2"],"max_severity":"oops"}]}]}]}`
	fs, err := parseOSV([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]finding.Severity{}
	for _, f := range fs {
		got[f.ID] = f.Severity
	}
	want := map[string]finding.Severity{"V1": finding.Critical, "V2": finding.Medium, "V3": finding.Medium}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestOSVFixedVersionMatchesPackage(t *testing.T) {
	raw := `{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"Go"},
	"vulnerabilities":[{"id":"V1","affected":[
	 {"package":{"name":"other","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"fixed":"9.9"}]}]},
	 {"package":{"name":"a","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"fixed":"8.8"}]}]},
	 {"package":{"name":"a","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2"},{"fixed":"3.0"}]}]}]}]}]}]}`
	fs, err := parseOSV([]byte(raw), "")
	if err != nil || len(fs) != 1 {
		t.Fatalf("%v %v", fs, err)
	}
	if fs[0].FixedVersion != "1.2" || !fs[0].FixAvailable {
		t.Fatalf("got %+v", fs[0])
	}
}

func TestOSVFileRelativeToDir(t *testing.T) {
	dir := t.TempDir()
	raw := `{"results":[{"source":{"path":"` + filepath.ToSlash(filepath.Join(dir, "sub", "go.mod")) + `"},"packages":[{"package":{"name":"a","version":"1","ecosystem":"Go"},"vulnerabilities":[{"id":"V1"}]}]}]}`
	fs, err := parseOSV([]byte(raw), dir)
	if err != nil || len(fs) != 1 || fs[0].File != "sub/go.mod" {
		t.Fatalf("%v %v", fs, err)
	}
}

// osvRunner writes golden to the --output-file argument (when non-nil).
func osvRunner(t *testing.T, golden []byte, code int, calls *int, argsOut *[]string) Runner {
	return func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
		if calls != nil {
			*calls++
		}
		if argsOut != nil {
			*argsOut = append([]string{name}, args...)
		}
		for i, a := range args {
			if a == "--output-file" && golden != nil {
				if err := os.WriteFile(args[i+1], golden, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return nil, []byte("SECRET-STDERR"), code, nil
	}
}

func TestOSVNoPackagesIsEmpty(t *testing.T) {
	noSleep(t)
	raw := t.TempDir()
	calls := 0
	s := NewOSV(osvRunner(t, nil, 128, &calls, nil))
	fs, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: raw})
	if err != nil || len(fs) != 0 || calls != 1 {
		t.Fatalf("fs=%v err=%v calls=%d", fs, err, calls)
	}
	b, err := os.ReadFile(filepath.Join(raw, "osv.json"))
	if err != nil {
		t.Fatal(err)
	}
	var back []finding.Finding
	if err := json.Unmarshal(b, &back); err != nil || len(back) != 0 {
		t.Fatalf("raw %s: %v", b, err)
	}
}

func TestOSVExit127IsError(t *testing.T) {
	noSleep(t)
	calls := 0
	s := NewOSV(osvRunner(t, nil, 127, &calls, nil))
	_, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()})
	if err == nil || calls != 3 {
		t.Fatalf("err=%v calls=%d (want 3 attempts)", err, calls)
	}
	if strings.Contains(err.Error(), "SECRET-STDERR") {
		t.Fatalf("stderr leaked: %v", err)
	}
}

func TestOSVExit1WithFindings(t *testing.T) {
	noSleep(t)
	raw := t.TempDir()
	dir := "/src"
	var args []string
	calls := 0
	s := NewOSV(osvRunner(t, osvGolden(t), 1, &calls, &args))
	fs, err := s.Scan(context.Background(), Target{Dir: dir, RawDir: raw})
	if err != nil || len(fs) != 6 || calls != 1 {
		t.Fatalf("fs=%d err=%v calls=%d", len(fs), err, calls)
	}
	if args[0] != "osv-scanner" || !reflect.DeepEqual(args[1:6], []string{"scan", "source", "-r", "--format", "json"}) ||
		args[6] != "--output-file" || args[len(args)-1] != "." {
		t.Fatalf("args %v", args)
	}
	if strings.HasPrefix(args[7], raw) || strings.HasPrefix(args[7], dir) {
		t.Fatalf("report inside raw dir: %v", args)
	}
	if _, err := os.Stat(args[7]); !os.IsNotExist(err) {
		t.Fatal("temp report not removed")
	}
	if _, err := os.Stat(filepath.Join(raw, "osv.json")); err != nil {
		t.Fatal(err)
	}
}

func TestOSVOfflineDB(t *testing.T) {
	t.Setenv("SHIPGUARD_OSV_OFFLINE_DB", "/db/osv")
	var args []string
	s := NewOSV(osvRunner(t, osvGolden(t), 0, nil, &args))
	if _, err := s.Scan(context.Background(), Target{Dir: "/src", RawDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--offline-vulnerabilities --local-db-path /db/osv") {
		t.Fatalf("args %v", args)
	}
}

func TestOSVRetriesRunnerErrorThenSucceeds(t *testing.T) {
	var sleeps []time.Duration
	old := osvSleep
	osvSleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	t.Cleanup(func() { osvSleep = old })
	calls := 0
	golden := osvGolden(t)
	run := func(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, int, error) {
		calls++
		if calls == 1 {
			return nil, nil, -1, errors.New("start failed")
		}
		if calls == 2 {
			return nil, nil, 2, nil
		}
		return osvRunner(t, golden, 1, nil, nil)(ctx, dir, name, args...)
	}
	fs, err := NewOSV(run).Scan(context.Background(), Target{Dir: "/src", RawDir: t.TempDir()})
	if err != nil || len(fs) != 6 || calls != 3 || len(sleeps) != 2 {
		t.Fatalf("fs=%d err=%v calls=%d sleeps=%v", len(fs), err, calls, sleeps)
	}
}

func TestOSVEmptyOutputIsError(t *testing.T) {
	noSleep(t)
	s := NewOSV(osvRunner(t, nil, 0, nil, nil))
	if _, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()}); err == nil {
		t.Fatal("want error when the tool wrote no output")
	}
}
