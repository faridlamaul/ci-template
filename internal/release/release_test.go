package release

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faridlamaul/shipguard/internal/policy"
)

type call struct {
	name string
	args []string
	env  []string
}

type fakeExec struct {
	calls      []call
	shiptag    string // contents written to --output-file
	gitTag     string // tags at HEAD, one per line; "" = none
	goreleaser error
	dryJSON    string // shiptag stdout
	shiptagErr error
	localTags  map[string]bool // tags present locally; nil = none
	tagFail    bool
	gitPath    string // output of git rev-parse --git-path; "" = .git/info/exclude
	gitPathErr error
}

func (f *fakeExec) Run(_ context.Context, _ string, env []string, _ io.Writer, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, args, env})
	switch filepath.Base(name) {
	case "shiptag":
		if f.shiptagErr != nil {
			return nil, f.shiptagErr
		}
		for i, a := range args {
			if a == "--output-file" && f.shiptag != "" {
				_ = os.WriteFile(args[i+1], []byte(f.shiptag), 0o600)
			}
		}
	case "git":
		switch args[0] {
		case "rev-parse":
			if has(args, "--git-path") {
				if f.gitPathErr != nil {
					return nil, f.gitPathErr
				}
				if f.gitPath == "" {
					return []byte(".git/info/exclude\n"), nil
				}
				return []byte(f.gitPath + "\n"), nil
			}
			if f.localTags[strings.TrimPrefix(args[len(args)-1], "refs/tags/")] {
				return nil, nil
			}
			return nil, errors.New("missing")
		case "tag":
			if has(args, "--points-at") { // headTag: gitTag lists the tags at HEAD, one per line
				if f.gitTag == "" {
					return nil, nil
				}
				return []byte(f.gitTag + "\n"), nil
			}
			if f.tagFail {
				return nil, errors.New("tag failed")
			}
			if f.localTags == nil {
				f.localTags = map[string]bool{}
			}
			f.localTags[args[1]] = true
			return nil, nil
		}
		return nil, errors.New("unexpected git command")
	case "goreleaser":
		return nil, f.goreleaser
	}
	if filepath.Base(name) == "shiptag" {
		return []byte(f.dryJSON), nil
	}
	return nil, nil
}

func (f *fakeExec) find(base string) *call {
	for i := range f.calls {
		if filepath.Base(f.calls[i].name) == base {
			return &f.calls[i]
		}
	}
	return nil
}

func opts(t *testing.T, f *fakeExec) Options {
	return Options{
		Dir:      t.TempDir(),
		CacheDir: t.TempDir(),
		Config:   policy.Defaults(),
		Tool: func(_ context.Context, n string) (string, error) {
			return "/tools/" + n + "/" + n, nil
		},
		Exec:   f,
		Getenv: func(k string) string { return map[string]string{"PATH": "/usr/bin"}[k] },
		Out:    io.Discard,
	}
}

func withGoreleaser(t *testing.T, o Options) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(o.Dir, ".goreleaser.yaml"), []byte("version: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func step(r Result, name string) StepResult {
	for _, s := range r.Steps {
		if s.Name == name {
			return s
		}
	}
	return StepResult{}
}

func has(args []string, a string) bool {
	for _, x := range args {
		if x == a {
			return true
		}
	}
	return false
}

func TestVersionReleased(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\nversion=1.4.0\n"}
	r, err := Run(context.Background(), opts(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Released || r.Tag != "v1.4.0" || r.Version != "1.4.0" {
		t.Fatalf("result = %+v", r)
	}
	c := f.find("shiptag")
	if c == nil || !has(c.args, "tag") || !has(c.args, "--output-file") {
		t.Fatalf("shiptag call = %+v", c)
	}
}

func TestVersionNothingNoTag(t *testing.T) {
	f := &fakeExec{shiptag: "released=false\n"}
	r, _ := Run(context.Background(), opts(t, f))
	if r.Released || r.ExitCode() != 0 {
		t.Fatalf("result = %+v", r)
	}
	for _, n := range []string{"binaries", "image"} {
		if s := step(r, n); s.Status != "skipped" || s.Reason != "nothing to release" {
			t.Fatalf("%s = %+v", n, s)
		}
	}
}

func TestVersionReuseHeadTag(t *testing.T) {
	f := &fakeExec{shiptag: "released=false\n", gitTag: "v1.4.0"}
	r, _ := Run(context.Background(), opts(t, f))
	if !r.Released || r.Tag != "v1.4.0" || !strings.Contains(step(r, "version").Reason, "re-run") {
		t.Fatalf("result = %+v", r)
	}
}

func TestDryRunNothingUsesPlaceholder(t *testing.T) {
	f := &fakeExec{}
	o := opts(t, f)
	o.DryRun = true
	called := false
	defer func(old func(context.Context, Options, *Result) StepResult) { imageStep = old }(imageStep)
	imageStep = func(context.Context, Options, *Result) StepResult {
		called = true
		return StepResult{Status: "skipped", Reason: "stub"}
	}
	r, _ := Run(context.Background(), o)
	if r.Version != "0.0.0-dryrun" || r.Released {
		t.Fatalf("result = %+v", r)
	}
	if !called || step(r, "image").Status != "skipped" {
		t.Fatalf("image step not invoked: %+v", r.Steps)
	}
	if !has(f.find("shiptag").args, "--dry-run") {
		t.Fatal("missing --dry-run")
	}
}

func TestBinariesSkippedWithoutConfig(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\n"}
	r, _ := Run(context.Background(), opts(t, f))
	if s := step(r, "binaries"); s.Status != "skipped" || f.find("goreleaser") != nil {
		t.Fatalf("binaries = %+v", s)
	}
}

func TestBinariesRuns(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\n"}
	o := opts(t, f)
	withGoreleaser(t, o)
	r, _ := Run(context.Background(), o)
	if step(r, "binaries").Status != "passed" {
		t.Fatalf("binaries = %+v", step(r, "binaries"))
	}
	c := f.find("goreleaser")
	if strings.Join(c.args, " ") != "release --clean" {
		t.Fatalf("args = %v", c.args)
	}
	if !has(c.env, "GORELEASER_CURRENT_TAG=v1.4.0") || !has(c.env, "PATH=/tools/cosign:/usr/bin") {
		t.Fatalf("env = %v", c.env)
	}
}

func TestBinariesDryRun(t *testing.T) {
	f := &fakeExec{}
	o := opts(t, f)
	o.DryRun = true
	withGoreleaser(t, o)
	_, _ = Run(context.Background(), o)
	if got := strings.Join(f.find("goreleaser").args, " "); got != "release --snapshot --clean --skip=publish" {
		t.Fatalf("args = %q", got)
	}
}

func TestFailureStopsLater(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\n", goreleaser: errors.New("boom")}
	o := opts(t, f)
	withGoreleaser(t, o)
	r, _ := Run(context.Background(), o)
	if step(r, "binaries").Status != "failed" || step(r, "image").Status != "not run" || r.ExitCode() != 1 {
		t.Fatalf("result = %+v", r)
	}
}

func TestUnknownStep(t *testing.T) {
	o := opts(t, &fakeExec{})
	o.Steps = []string{"deploy"}
	if _, err := Run(context.Background(), o); err == nil {
		t.Fatal("want error")
	}
}

func TestPrereleaseFlag(t *testing.T) {
	f := &fakeExec{shiptag: "released=false\n"}
	o := opts(t, f)
	o.Prerelease = "rc"
	_, _ = Run(context.Background(), o)
	a := f.find("shiptag").args
	i := 0
	for ; i < len(a) && a[i] != "--prerelease"; i++ {
	}
	if i+1 >= len(a) || a[i+1] != "rc" {
		t.Fatalf("args = %v", a)
	}
}

func TestDryRunKeepsRealNextVersion(t *testing.T) {
	f := &fakeExec{dryJSON: `{"released":false,"next_tag":"v1.5.0","version":"1.5.0"}`}
	o := opts(t, f)
	o.DryRun = true
	withGoreleaser(t, o)
	r, _ := Run(context.Background(), o)
	if r.Released || r.Tag != "v1.5.0" || r.Version != "1.5.0" {
		t.Fatalf("result = %+v", r)
	}
	a := f.find("shiptag").args
	if !has(a, "--dry-run") || !has(a, "--json") || has(a, "--output-file") {
		t.Fatalf("args = %v", a)
	}
	if !has(f.find("goreleaser").env, "GORELEASER_CURRENT_TAG=v1.5.0") {
		t.Fatalf("env = %v", f.find("goreleaser").env)
	}
	if f.localTags["v1.5.0"] {
		t.Fatal("dry run must not create a tag")
	}
}

func TestReleasedCreatesLocalTag(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\n"}
	r, _ := Run(context.Background(), opts(t, f))
	if !f.localTags["v1.4.0"] || step(r, "version").Status != "passed" {
		t.Fatalf("tags = %v, steps = %+v", f.localTags, r.Steps)
	}
}

func TestReleasedKeepsExistingLocalTag(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\n", localTags: map[string]bool{"v1.4.0": true}}
	_, _ = Run(context.Background(), opts(t, f))
	for _, c := range f.calls {
		if c.name == "git" && c.args[0] == "tag" {
			t.Fatal("tag recreated")
		}
	}
}

func TestLocalTagFailureFailsVersion(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\n", tagFail: true}
	r, _ := Run(context.Background(), opts(t, f))
	if step(r, "version").Status != "failed" || step(r, "binaries").Status != "not run" {
		t.Fatalf("steps = %+v", r.Steps)
	}
}

func TestNotReleasedWithExistingTagOutput(t *testing.T) {
	f := &fakeExec{shiptag: "released=false\ntag=v1.4.0\n"}
	r, _ := Run(context.Background(), opts(t, f))
	if !r.Released || r.Tag != "v1.4.0" || !strings.Contains(step(r, "version").Reason, "re-run") || !f.localTags["v1.4.0"] {
		t.Fatalf("result = %+v tags=%v", r, f.localTags)
	}
}

func TestBinariesPathWithoutExistingPath(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\n"}
	o := opts(t, f)
	o.Getenv = func(string) string { return "" }
	withGoreleaser(t, o)
	_, _ = Run(context.Background(), o)
	if !has(f.find("goreleaser").env, "PATH=/tools/cosign") {
		t.Fatalf("env = %v", f.find("goreleaser").env)
	}
}

func TestShiptagFails(t *testing.T) {
	f := &fakeExec{shiptagErr: errors.New("boom")}
	r, _ := Run(context.Background(), opts(t, f))
	if step(r, "version").Status != "failed" || step(r, "binaries").Status != "not run" ||
		step(r, "image").Status != "not run" || r.ExitCode() != 1 {
		t.Fatalf("steps = %+v", r.Steps)
	}
}

func TestShiptagInvalidTag(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=1.4\n"}
	r, _ := Run(context.Background(), opts(t, f))
	if step(r, "version").Status != "failed" || r.ExitCode() != 1 {
		t.Fatalf("steps = %+v", r.Steps)
	}
}

func TestMissingOutputFileFails(t *testing.T) {
	f := &fakeExec{} // shiptag writes nothing
	r, _ := Run(context.Background(), opts(t, f))
	if step(r, "version").Status != "failed" {
		t.Fatalf("steps = %+v", r.Steps)
	}
}

func TestVersionNotSelected(t *testing.T) {
	f := &fakeExec{gitTag: "v1.4.0"}
	o := opts(t, f)
	o.Steps = []string{"binaries"}
	withGoreleaser(t, o)
	r, _ := Run(context.Background(), o)
	if f.find("shiptag") != nil || r.Tag != "v1.4.0" || step(r, "version").Status != "skipped" ||
		step(r, "binaries").Status != "passed" {
		t.Fatalf("result = %+v", r)
	}

	f = &fakeExec{}
	o = opts(t, f)
	o.Steps = []string{"binaries"}
	r, _ = Run(context.Background(), o)
	if s := step(r, "binaries"); s.Status != "skipped" || s.Reason != "no release tag at HEAD (version step not selected)" {
		t.Fatalf("binaries = %+v", s)
	}
}

func TestDryRunHeadTagNeverReleased(t *testing.T) {
	for _, steps := range [][]string{nil, {"binaries"}} {
		f := &fakeExec{gitTag: "v1.4.0"}
		o := opts(t, f)
		o.DryRun = true
		o.Steps = steps
		r, _ := Run(context.Background(), o)
		if r.Released || r.Tag != "v1.4.0" || r.Version != "1.4.0" {
			t.Fatalf("steps %v: result = %+v", steps, r)
		}
	}
}

func TestHeadTagPrefersHighestStable(t *testing.T) {
	for name, tags := range map[string]string{
		"stable beats prerelease":   "v1.4.0-rc.1\nv1.4.0",
		"stable beats prerelease 2": "v1.4.0\nv1.4.0-rc.1",
		"highest stable":            "v1.4.0\nv1.10.0\nv1.9.9",
		"highest prerelease":        "v2.0.0-rc.1\nv2.0.0-rc.10\nv2.0.0-rc.2",
		"junk ignored":              "latest\nv1.2.3\nv1.2",
	} {
		want := map[string]string{
			"stable beats prerelease": "v1.4.0", "stable beats prerelease 2": "v1.4.0",
			"highest stable": "v1.10.0", "highest prerelease": "v2.0.0-rc.10", "junk ignored": "v1.2.3",
		}[name]
		f := &fakeExec{gitTag: tags}
		if got := headTag(context.Background(), opts(t, f)); got != want {
			t.Errorf("%s: headTag = %q, want %q", name, got, want)
		}
	}
	if got := headTag(context.Background(), opts(t, &fakeExec{})); got != "" {
		t.Errorf("no tags: headTag = %q", got)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func TestBinariesExcludesShipguardPaths(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\n", gitPath: "info/exclude"} // relative to Dir
	o := opts(t, f)
	withGoreleaser(t, o)
	for i := 0; i < 2; i++ { // the second run proves idempotence
		r, _ := Run(context.Background(), o)
		if step(r, "binaries").Status != "passed" {
			t.Fatalf("run %d: binaries = %+v", i, step(r, "binaries"))
		}
	}
	got := readLines(t, filepath.Join(o.Dir, "info", "exclude"))
	if strings.Join(got, "|") != ".shipguard/|.shipguard-cache/|.shipguard-action/" {
		t.Fatalf("exclude = %q", got)
	}
}

func TestBinariesExcludeKeepsExistingLines(t *testing.T) {
	o := opts(t, &fakeExec{shiptag: "released=true\ntag=v1.4.0\n", gitPath: filepath.Join(t.TempDir(), "git", "info", "exclude")})
	f := o.Exec.(*fakeExec)
	if err := os.MkdirAll(filepath.Dir(f.gitPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.gitPath, []byte("# mine\n.shipguard-cache/\nbuild"), 0o644); err != nil { // no trailing newline
		t.Fatal(err)
	}
	withGoreleaser(t, o)
	r, _ := Run(context.Background(), o)
	if step(r, "binaries").Status != "passed" {
		t.Fatalf("binaries = %+v", step(r, "binaries"))
	}
	got := strings.Join(readLines(t, f.gitPath), "|")
	if got != "# mine|.shipguard-cache/|build|.shipguard/|.shipguard-action/" {
		t.Fatalf("exclude = %q", got)
	}
}

func TestBinariesExcludeFailureFailsStep(t *testing.T) {
	f := &fakeExec{shiptag: "released=true\ntag=v1.4.0\n", gitPathErr: errors.New("not a git repository")}
	o := opts(t, f)
	withGoreleaser(t, o)
	r, _ := Run(context.Background(), o)
	s := step(r, "binaries")
	if s.Status != "failed" || !strings.Contains(s.Reason, "info/exclude") || !strings.Contains(s.Reason, "not a git repository") {
		t.Fatalf("binaries = %+v", s)
	}
	if f.find("goreleaser") != nil || step(r, "image").Status != "not run" {
		t.Fatalf("goreleaser ran or image not skipped: %+v", r.Steps)
	}
}

func TestCacheRoot(t *testing.T) {
	got, err := CacheRoot(func(k string) string { return map[string]string{"RUNNER_TEMP": "/runner/tmp"}[k] })
	if err != nil || got != "/runner/tmp/shipguard-cache" {
		t.Fatalf("with RUNNER_TEMP: %q, %v", got, err)
	}
	user, uerr := os.UserCacheDir()
	if uerr != nil {
		t.Skip("no user cache dir")
	}
	got, err = CacheRoot(func(string) string { return "" })
	if err != nil || got != filepath.Join(user, "shipguard") {
		t.Fatalf("without RUNNER_TEMP: %q, %v", got, err)
	}
}
