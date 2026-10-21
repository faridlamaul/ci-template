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
	// Six advisories in three alias groups: one finding per group.
	if len(fs) != 3 {
		t.Fatalf("want 3 findings (package x alias group), got %d: %+v", len(fs), fs)
	}
	fixed := byID["PYSEC-2018-66"]
	if fixed.Package != "flask" || fixed.Version != "0.12.2" || fixed.FixedVersion != "0.12.3" || !fixed.FixAvailable ||
		fixed.Severity != finding.High || !reflect.DeepEqual(fixed.Aliases, []string{"CVE-2018-1000656", "GHSA-562c-5r94-xh97"}) ||
		fixed.Fingerprint != finding.Fingerprint("PYSEC-2018-66", "requirements.txt", "flask@0.12.2") {
		t.Fatalf("fixed finding %+v", fixed)
	}
	unfixed := byID["PYSEC-2018-97"]
	if unfixed.Package != "pycrypto" || unfixed.FixedVersion != "" || unfixed.FixAvailable || unfixed.Severity != finding.High ||
		!reflect.DeepEqual(unfixed.Aliases, []string{"CVE-2018-6594", "GHSA-6528-wvf6-f6qg"}) {
		t.Fatalf("unfixed finding %+v", unfixed)
	}
	// A git-commit "fixed" event in a GIT range is not a fixed version.
	if g := byID["PYSEC-2017-94"]; g.FixedVersion != "" || g.FixAvailable || g.Severity != finding.Critical {
		t.Fatalf("git range finding %+v", g)
	}
}

// TestParseOSVDedupesReal270 uses osv-scanner 2.7.0 output for
// requirements.txt "PyYAML==5.3": the file is reported twice (type lockfile,
// version 5.3, and type unknown, version 5.3.0), each with a PYSEC and a GHSA
// advisory per vulnerability.
func TestParseOSVDedupesReal270(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "osv", "python-dup-2.7.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := parseOSV(b, "/src")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"PYSEC-2020-96":  {"CVE-2020-1747", "GHSA-6757-jp84-gxfx"},
		"PYSEC-2021-142": {"CVE-2020-14343", "GHSA-8q59-q68h-6hv4"},
	}
	if len(fs) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(fs), len(want), fs)
	}
	for _, f := range fs {
		if !reflect.DeepEqual(f.Aliases, want[f.ID]) || f.File != "requirements.txt" || f.Package != "pyyaml" ||
			f.Version != "5.3" || f.Severity != finding.Critical {
			t.Errorf("finding %+v; want aliases %v", f, want[f.ID])
		}
	}
}

func TestParseOSVDedupeKeepsDistinctVersions(t *testing.T) {
	raw := `{"results":[{"source":{"path":"package-lock.json"},"packages":[
	 {"package":{"name":"a","version":"1.0.0","ecosystem":"npm"},"vulnerabilities":[{"id":"V1"}]},
	 {"package":{"name":"a","version":"1.0","ecosystem":"npm"},"vulnerabilities":[{"id":"V1","aliases":["CVE-1"]}]},
	 {"package":{"name":"a","version":"1.1.0","ecosystem":"npm"},"vulnerabilities":[{"id":"V1"}]}]}]}`
	fs, err := parseOSV([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[0].Version != "1.0.0" || fs[1].Version != "1.1.0" ||
		!reflect.DeepEqual(fs[0].Aliases, []string{"CVE-1"}) {
		t.Fatalf("got %+v", fs)
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
	if err != nil || len(fs) != 3 || calls != 1 {
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
	if err != nil || len(fs) != 3 || calls != 3 || len(sleeps) != 2 {
		t.Fatalf("fs=%d err=%v calls=%d sleeps=%v", len(fs), err, calls, sleeps)
	}
}

// TestOSVNeutralizesRepoConfig checks that the repository cannot tune
// osv-scanner: the config is an empty file outside the repository and
// .gitignore does not hide lockfiles.
func TestOSVNeutralizesRepoConfig(t *testing.T) {
	noSleep(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "osv-scanner.toml"), []byte("[[PackageOverrides]]\nignore = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var cfg string
	var cfgContent []byte
	var args []string
	inner := osvRunner(t, osvGolden(t), 1, nil, &args)
	run := func(ctx context.Context, d, name string, a ...string) ([]byte, []byte, int, error) {
		cfg = argAfter(a, "--config")
		var err error
		if cfgContent, err = os.ReadFile(cfg); err != nil {
			t.Fatalf("config: %v", err)
		}
		return inner(ctx, d, name, a...)
	}
	if _, err := NewOSV(run).Scan(context.Background(), Target{Dir: dir, RawDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if cfg == "" || within(dir, cfg) || len(cfgContent) != 0 {
		t.Fatalf("config %q (content %q) must be an empty file outside the repository", cfg, cfgContent)
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatalf("temp config not removed: %v", err)
	}
	if !contains(args, "--no-ignore") {
		t.Fatalf("args %v lack --no-ignore", args)
	}
}

// TestOSVExtractionErrorIsError: osv-scanner reports a lockfile it cannot
// parse only on stderr, and may still exit 0, 1 or 128 ("no packages").
func TestOSVExtractionErrorIsError(t *testing.T) {
	noSleep(t)
	stderr := "Scanning dir .\nError during extraction: (extracting as javascript/packagelockjson) src/package-lock.json: could not extract: invalid character 't'\n"
	for _, code := range []int{0, 1, 128} {
		calls := 0
		run := func(ctx context.Context, d, name string, a ...string) ([]byte, []byte, int, error) {
			calls++
			if out := argAfter(a, "--output-file"); out != "" && code != 128 {
				if err := os.WriteFile(out, []byte(`{"results":[]}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			return nil, []byte(stderr), code, nil
		}
		fs, err := NewOSV(run).Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()})
		if err == nil || fs != nil {
			t.Fatalf("exit %d: want error, got fs=%v err=%v", code, fs, err)
		}
		if strings.Contains(err.Error(), "package-lock") || strings.Contains(err.Error(), "invalid character") {
			t.Fatalf("exit %d: stderr leaked into error: %v", code, err)
		}
		if calls != 1 {
			t.Fatalf("exit %d: calls = %d, want 1 (not retried)", code, calls)
		}
	}
}

func TestOSVEmptyOutputIsError(t *testing.T) {
	noSleep(t)
	s := NewOSV(osvRunner(t, nil, 0, nil, nil))
	if _, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()}); err == nil {
		t.Fatal("want error when the tool wrote no output")
	}
}

// osvExtractionRunner reports the given stderr with exit code 0 and an empty
// report, and records its arguments.
func osvExtractionRunner(t *testing.T, stderr string, args *[]string) Runner {
	return func(ctx context.Context, d, name string, a ...string) ([]byte, []byte, int, error) {
		if args != nil {
			*args = a
		}
		if out := argAfter(a, "--output-file"); out != "" {
			if err := os.WriteFile(out, []byte(`{"results":[]}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return nil, []byte(stderr), 0, nil
	}
}

// TestOSVPassesDirectoryExcludes: osv-scanner 2.7.0 walks everything, so the
// directory-shaped excludes go to --x-exclude. A plain value is a path
// relative to the scan root; "g:" is a glob matched against the full path, so
// rooted globs cannot be expressed and **/X/** becomes g:**/X. File-shaped
// excludes are left to the findings filter.
func TestOSVPassesDirectoryExcludes(t *testing.T) {
	var args []string
	run := osvExtractionRunner(t, "", &args)
	_, err := NewOSV(run).Scan(context.Background(), Target{
		Dir: t.TempDir(), RawDir: t.TempDir(),
		Exclude: []string{"vendor/", "a/b/", "**/testdata/**", "*.gen.lock", "go.sum", ".shipguard-cache/", "**/node_modules/**", "docs/*/x/**"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i, a := range args {
		if a == "--x-exclude" {
			got = append(got, args[i+1])
		}
	}
	want := []string{"vendor", "a/b", "g:**/testdata", ".shipguard-cache", "g:**/node_modules"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("--x-exclude = %v, want %v (args %v)", got, want, args)
	}
	if args[len(args)-1] != "." {
		t.Fatalf("args %v must end with the scan root", args)
	}
}

// TestOSVExtractionErrorAlwaysFails: stderr path text is repository-controlled
// (newlines are legal in names), so no extraction error is ever ignored and the error carries no stderr text.
func TestOSVExtractionErrorAlwaysFails(t *testing.T) {
	noSleep(t)
	dir := t.TempDir()
	root := strings.TrimPrefix(dir, "/")
	head := "Error during extraction: (extracting as javascript/packagelockjson) \n"
	cases := map[string]string{
		"real forged two-line":      head + "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80\xe2\x94\xa4" + root + "/web\n" + root + "/testdata/package-lock.json: could not extract: invalid character 'b'\n",
		"dir named like the marker": head + root + "/docs: could not extract/package-lock.json: could not extract: bad\n",
		"forged web/* lines":        head + root + "/web/a: could not extract: x\n" + root + "/web/tmp/package-lock.json: could not extract: bad\n",
		"excluded looking path":     head + "\t" + root + "/testdata/package-lock.json: could not extract: bad\n",
		"header only":               "Error during extraction: something else\n",
	}
	for name, stderr := range cases {
		{
			t.Run(name, func(t *testing.T) {
				fs, err := NewOSV(osvExtractionRunner(t, stderr, nil)).Scan(context.Background(), Target{
					Dir: dir, RawDir: t.TempDir(), Exclude: []string{"testdata/", "web/*", "**/web/**"}})
				if err == nil || fs != nil || strings.Contains(err.Error(), "package-lock") || strings.Contains(err.Error(), root) {
					t.Fatalf("fs=%v err=%v", fs, err)
				}
			})
		}
	}
}

// TestOSVExcludedDirIsNotWalked: an excluded directory is handed to osv-scanner
// as --x-exclude, so no extraction error comes from it and a clean run passes.
func TestOSVExcludedDirIsNotWalked(t *testing.T) {
	var args []string
	fs, err := NewOSV(osvExtractionRunner(t, "Scanning dir .\n", &args)).Scan(context.Background(), Target{
		Dir: t.TempDir(), RawDir: t.TempDir(), Exclude: []string{"testdata/"}})
	if err != nil || len(fs) != 0 || !reflect.DeepEqual(args[len(args)-3:], []string{"--x-exclude", "testdata", "."}) {
		t.Fatalf("fs=%v err=%v args=%v", fs, err, args)
	}
}

func TestOSVFixedForInstalledVersion(t *testing.T) {
	const twoRanges = `{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"1.2"}]},
		{"type":"ECOSYSTEM","events":[{"introduced":"2.0"},{"fixed":"2.3"}]}`
	cases := []struct {
		name, pkg, version, ecosystem, advisory, ranges, want string
	}{
		{"second range", "a", "2.1", "PyPI", "a", twoRanges, "2.3"},
		{"first range", "a", "1.1", "PyPI", "a", twoRanges, "1.2"},
		{"pre-release before release", "a", "2.3-rc1", "npm", "a", twoRanges, "2.3"},
		{"numeric not lexical", "a", "1.10", "npm", "a",
			`{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.9"},{"introduced":"1.10"},{"fixed":"1.11"}]}`, "1.11"},
		{"single range of pairs", "a", "2.1", "Go", "a",
			`{"type":"SEMVER","events":[{"introduced":"1.0"},{"fixed":"1.2"},{"introduced":"2.0"},{"fixed":"2.3"}]}`, "2.3"},
		{"git range ignored", "a", "2.1", "Go", "a",
			`{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc123"}]},` + twoRanges, "2.3"},
		{"PyPI PEP 503 case", "PyYAML", "2.1", "PyPI", "pyyaml", twoRanges, "2.3"},
		{"PyPI PEP 503 separators", "ruamel_yaml", "2.1", "PyPI", "ruamel-yaml", twoRanges, "2.3"},
		{"PyPI separator runs", "a.-_b", "2.1", "PyPI", "A-b", twoRanges, "2.3"},
		{"npm names exact", "Foo", "2.1", "npm", "foo", twoRanges, ""},
		{"unparseable version uses first fix", "a", "not a version", "PyPI", "a", twoRanges, "1.2"},
		{"version in no range uses first fix", "a", "3.0", "PyPI", "a", twoRanges, "1.2"},
		{"last_affected only has no fix", "a", "1.1", "PyPI", "a",
			`{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"1.5"}]}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := `{"results":[{"source":{"path":"requirements.txt"},"packages":[{"package":{"name":"` + c.pkg +
				`","version":"` + c.version + `","ecosystem":"` + c.ecosystem + `"},
				"vulnerabilities":[{"id":"V1","affected":[{"package":{"name":"` + c.advisory +
				`","ecosystem":"` + c.ecosystem + `"},"ranges":[` + c.ranges + `]}]}]}]}]}`
			fs, err := parseOSV([]byte(raw), "")
			if err != nil || len(fs) != 1 {
				t.Fatalf("%v %v", fs, err)
			}
			if fs[0].FixedVersion != c.want || fs[0].FixAvailable != (c.want != "") {
				t.Fatalf("fixed = %q, available = %v; want %q", fs[0].FixedVersion, fs[0].FixAvailable, c.want)
			}
		})
	}
}

func TestOSVCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2", "1.2", 0},
		{"1.2", "1.2.0", 0},
		{"1.9", "1.10", -1},
		{"2.0", "1.10", 1},
		{"1.0-rc1", "1.0", -1},
		{"1.0", "1.0-rc1", 1},
		{"1.0-alpha", "1.0-beta", -1},
		{"v1.2.3", "1.2.4", -1},
		{"1.0+build1", "1.0", 0},
	}
	for _, c := range cases {
		got, ok := compareVersions(c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, %v; want %d", c.a, c.b, got, ok, c.want)
		}
	}
	for _, bad := range []string{"", "not a version", "1..2", "abc"} {
		if _, ok := compareVersions(bad, "1.0"); ok {
			t.Errorf("compareVersions(%q) ok, want unparseable", bad)
		}
	}
}

// TestOSVExit1WithoutFindingsIsError: osv-scanner exits 1 only when it
// reports vulnerabilities, so a well-formed report with none is inconsistent
// and must not pass as clean.
func TestOSVExit1WithoutFindingsIsError(t *testing.T) {
	noSleep(t)
	calls := 0
	s := NewOSV(osvRunner(t, []byte(`{"results":[]}`), 1, &calls, nil))
	if _, err := s.Scan(context.Background(), Target{Dir: t.TempDir(), RawDir: t.TempDir()}); err == nil {
		t.Fatal("exit 1 with an empty report passed as clean")
	}
}
