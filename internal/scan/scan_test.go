package scan

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/platform"
	"github.com/faridlamaul/shipguard/internal/policy"
	"github.com/faridlamaul/shipguard/internal/scanner"
	"github.com/faridlamaul/shipguard/internal/testutil/gitfixture"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// fake is a Scanner that returns canned results for the head directory and
// for any other directory (the base worktree), and records every Target.
type fake struct {
	name    string
	cat     finding.Category
	headDir string
	head    []finding.Finding
	base    []finding.Finding
	headErr error
	baseErr error
	targets []scanner.Target
}

func (f *fake) Name() string               { return f.name }
func (f *fake) Category() finding.Category { return f.cat }
func (f *fake) Scan(_ context.Context, t scanner.Target) ([]finding.Finding, error) {
	f.targets = append(f.targets, t)
	if t.Dir == f.headDir {
		return slices.Clone(f.head), f.headErr
	}
	return slices.Clone(f.base), f.baseErr
}

func (f *fake) baseTargets() []scanner.Target {
	var out []scanner.Target
	for _, t := range f.targets {
		if t.Dir != f.headDir {
			out = append(out, t)
		}
	}
	return out
}

func fnd(scannerName string, cat finding.Category, id, file string) finding.Finding {
	return finding.Finding{
		ID: id, Scanner: scannerName, Category: cat, Severity: finding.High, File: file, Message: "m",
		Fingerprint: finding.Fingerprint(id, file, ""),
	}
}

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

// commitFile writes content to path in r and commits it; empty content deletes it.
func commitFile(r *gitfixture.Repo, path, content string) string {
	r.T.Helper()
	p := filepath.Join(r.Dir, path)
	if content == "" {
		r.Git("rm", "-q", "--", path)
	} else {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			r.T.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			r.T.Fatal(err)
		}
		r.Git("add", "--", path)
	}
	r.Git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "edit "+path)
	return r.Git("rev-parse", "HEAD")
}

// prRepo builds main (base) and a checked-out feature branch (head). baseCfg
// and headCfg are the .shipguard.yaml contents ("" = absent).
func prRepo(t *testing.T, baseCfg, headCfg string) (r *gitfixture.Repo, baseSHA string) {
	t.Helper()
	isolate(t)
	r = gitfixture.New(t)
	baseSHA = r.Commit("base", "src/a.go")
	if baseCfg != "" {
		baseSHA = commitFile(r, ".shipguard.yaml", baseCfg)
	}
	r.Git("checkout", "-q", "-b", "feature")
	r.Commit("head", "src/b.go")
	if headCfg != baseCfg {
		commitFile(r, ".shipguard.yaml", headCfg)
	}
	return r, baseSHA
}

func prCtx() platform.Context {
	return platform.Context{Platform: "github", Event: platform.EventPR, BaseRef: "main"}
}

func allCats() []finding.Category {
	return []finding.Category{finding.CategorySecrets, finding.CategorySAST, finding.CategorySCA, finding.CategoryIaC}
}

func fixedNow() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }

func runScan(t *testing.T, o Options) (finding.Result, policy.Config) {
	t.Helper()
	if o.Categories == nil {
		o.Categories = allCats()
	}
	if o.Now == nil {
		o.Now = fixedNow
	}
	res, cfg, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res, cfg
}

func runOf(t *testing.T, res finding.Result, name string) finding.ScannerRun {
	t.Helper()
	for _, r := range res.Scanners {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no ScannerRun %q in %+v", name, res.Scanners)
	return finding.ScannerRun{}
}

func statusOf(t *testing.T, res finding.Result, id string) finding.Status {
	t.Helper()
	for _, f := range res.Findings {
		if f.ID == id {
			return f.Status
		}
	}
	t.Fatalf("finding %q not in result", id)
	return ""
}

func assertNoEmptyStatus(t *testing.T, res finding.Result) {
	t.Helper()
	for _, f := range res.Findings {
		if f.Status != finding.StatusNew && f.Status != finding.StatusExisting {
			t.Errorf("finding %s has status %q on a PR; want new or existing", f.ID, f.Status)
		}
	}
}

func TestScanPRMarksNewAndExisting(t *testing.T) {
	r, baseSHA := prRepo(t, "", "")
	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir,
		head: []finding.Finding{fnd("opengrep", finding.CategorySAST, "old", "src/a.go"), fnd("opengrep", finding.CategorySAST, "fresh", "src/b.go")},
		base: []finding.Finding{fnd("opengrep", finding.CategorySAST, "old", "src/a.go")}}
	sca := &fake{name: "osv-scanner", cat: finding.CategorySCA, headDir: r.Dir,
		head: []finding.Finding{fnd("osv-scanner", finding.CategorySCA, "cve", "go.mod")},
		base: []finding.Finding{fnd("osv-scanner", finding.CategorySCA, "cve", "go.mod")}}
	secrets := &fake{name: "gitleaks", cat: finding.CategorySecrets, headDir: r.Dir,
		head: []finding.Finding{fnd("gitleaks", finding.CategorySecrets, "leak", "src/a.go")},
		base: []finding.Finding{fnd("gitleaks", finding.CategorySecrets, "leak", "src/a.go")}}

	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: prCtx(), Scanners: []scanner.Scanner{secrets, sast, sca}})

	if got := statusOf(t, res, "old"); got != finding.StatusExisting {
		t.Errorf("old: %q, want existing", got)
	}
	if got := statusOf(t, res, "fresh"); got != finding.StatusNew {
		t.Errorf("fresh: %q, want new", got)
	}
	if got := statusOf(t, res, "cve"); got != finding.StatusExisting {
		t.Errorf("cve: %q, want existing", got)
	}
	if got := statusOf(t, res, "leak"); got != finding.StatusNew {
		t.Errorf("leak: %q, want new (secrets are always new on a PR)", got)
	}
	assertNoEmptyStatus(t, res)
	validFindingsJSON(t, r.Dir)

	if len(secrets.targets) != 1 || secrets.targets[0].LogOpts != baseSHA+"..HEAD" {
		t.Errorf("secrets targets = %+v, want one head scan with LogOpts %s..HEAD", secrets.targets, baseSHA)
	}
	bt := sast.baseTargets()
	if len(bt) != 1 {
		t.Fatalf("sast base scans = %d, want 1", len(bt))
	}
	headRaw := filepath.Join(r.Dir, ".shipguard", "raw")
	if bt[0].RawDir == headRaw || bt[0].RawDir == "" {
		t.Errorf("base RawDir = %q, must be a separate temp dir", bt[0].RawDir)
	}
	if _, err := os.Stat(bt[0].Dir); !os.IsNotExist(err) {
		t.Errorf("base worktree %s not cleaned up: %v", bt[0].Dir, err)
	}
	if _, err := os.Stat(bt[0].RawDir); !os.IsNotExist(err) {
		t.Errorf("base raw dir %s not cleaned up: %v", bt[0].RawDir, err)
	}
	for _, run := range res.Scanners {
		if run.Status != "ok" {
			t.Errorf("run %+v, want ok", run)
		}
	}
}

func TestScanPRBaseScanErrorKeepsNew(t *testing.T) {
	r, _ := prRepo(t, "", "")
	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir,
		head:    []finding.Finding{fnd("opengrep", finding.CategorySAST, "old", "src/a.go")},
		base:    []finding.Finding{fnd("opengrep", finding.CategorySAST, "old", "src/a.go")},
		baseErr: errors.New("opengrep exited with code 7")}

	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: prCtx(), Scanners: []scanner.Scanner{sast}})

	run := runOf(t, res, "opengrep")
	if run.Status != "error" || !strings.HasPrefix(run.Error, "base scan failed: ") {
		t.Errorf("run = %+v, want error with \"base scan failed: \" prefix", run)
	}
	if got := statusOf(t, res, "old"); got != finding.StatusNew {
		t.Errorf("old: %q, want new when the base scan failed", got)
	}
	assertNoEmptyStatus(t, res)
}

func TestScanPRUsesBasePolicy(t *testing.T) {
	r, _ := prRepo(t, "version: 1\nmode: enforce\n", "version: 1\nmode: audit\n")
	res, cfg := runScan(t, Options{Dir: r.Dir, Ctx: prCtx()})

	if cfg.Mode != "enforce" {
		t.Errorf("mode = %q, want enforce (from base)", cfg.Mode)
	}
	if !res.PolicyChanged {
		t.Error("PolicyChanged = false, want true")
	}
	if !strings.Contains(res.PolicyDiff, "-mode: enforce") || !strings.Contains(res.PolicyDiff, "+mode: audit") {
		t.Errorf("PolicyDiff = %q", res.PolicyDiff)
	}
	b, err := os.ReadFile(filepath.Join(r.Dir, ".shipguard", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "version: 1\nmode: enforce\n" {
		t.Errorf("policy.yaml = %q, want the base bytes", b)
	}
}

func TestScanPRPolicyUnchanged(t *testing.T) {
	r, _ := prRepo(t, "version: 1\nmode: audit\n", "version: 1\nmode: audit\n")
	res, cfg := runScan(t, Options{Dir: r.Dir, Ctx: prCtx()})
	if res.PolicyChanged || res.PolicyDiff != "" || cfg.Mode != "audit" {
		t.Errorf("changed=%v diff=%q mode=%q", res.PolicyChanged, res.PolicyDiff, cfg.Mode)
	}
}

func TestScanPRPolicyAddedUsesDefaults(t *testing.T) {
	r, _ := prRepo(t, "", "version: 1\nmode: audit\nscanners:\n  sast:\n    enabled: false\n")
	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir,
		head: []finding.Finding{fnd("opengrep", finding.CategorySAST, "x", "src/b.go")}}
	res, cfg := runScan(t, Options{Dir: r.Dir, Ctx: prCtx(), Scanners: []scanner.Scanner{sast}})

	if cfg.Mode != "enforce" || !cfg.Scanners.SAST.Enabled {
		t.Errorf("cfg mode=%q sast=%v, want defaults", cfg.Mode, cfg.Scanners.SAST.Enabled)
	}
	if !res.PolicyChanged || !strings.Contains(res.PolicyDiff, "+mode: audit") {
		t.Errorf("changed=%v diff=%q", res.PolicyChanged, res.PolicyDiff)
	}
	if run := runOf(t, res, "opengrep"); run.Status != "ok" {
		t.Errorf("opengrep run = %+v, want ok (head cannot disable its own scanner)", run)
	}
	b, err := os.ReadFile(filepath.Join(r.Dir, ".shipguard", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := policy.Parse(b)
	if err != nil {
		t.Fatalf("policy.yaml does not parse: %v\n%s", err, b)
	}
	if got.Mode != "enforce" || !got.Scanners.SAST.Enabled {
		t.Errorf("policy.yaml = %q, want defaults", b)
	}
}

func TestScanPRMissingBaseFailsClosed(t *testing.T) {
	r, _ := prRepo(t, "", "")
	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir}
	ctx := prCtx()
	ctx.BaseRef = "nope"
	_, _, err := Run(context.Background(), Options{Dir: r.Dir, Ctx: ctx, Categories: allCats(), Scanners: []scanner.Scanner{sast}, Now: fixedNow})
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v, want an error naming nope", err)
	}
	if len(sast.targets) != 0 {
		t.Error("scanners ran although the base ref did not resolve")
	}
	if _, err := os.Stat(filepath.Join(r.Dir, ".shipguard", "findings.json")); !os.IsNotExist(err) {
		t.Errorf("findings.json written on base-resolution failure: %v", err)
	}
}

func TestScanPREmptyBaseRefFailsClosed(t *testing.T) {
	r, _ := prRepo(t, "", "")
	ctx := prCtx()
	ctx.BaseRef = ""
	if _, _, err := Run(context.Background(), Options{Dir: r.Dir, Ctx: ctx, Categories: allCats(), Now: fixedNow}); err == nil {
		t.Fatal("want error for a PR without a base ref")
	}
}

// shallowClone returns a depth-1 clone of the feature branch of an origin
// with main (two commits) and feature, plus main's SHA.
func shallowClone(t *testing.T, extra ...string) (dir, mainSHA string) {
	t.Helper()
	isolate(t)
	origin := gitfixture.New(t)
	origin.Commit("one", "a.txt")
	mainSHA = origin.Commit("two", "a.txt")
	origin.Git("checkout", "-q", "-b", "feature")
	origin.Commit("feat", "b.txt")
	origin.Git("checkout", "-q", "main")
	dir = filepath.Join(t.TempDir(), "clone")
	origin.Git(append(append([]string{"clone", "-q", "--depth", "1", "--branch", "feature"}, extra...), "file://"+origin.Dir, dir)...)
	return dir, mainSHA
}

func isShallow(t *testing.T, dir string) bool {
	t.Helper()
	return (&gitfixture.Repo{T: t, Dir: dir}).Git("rev-parse", "--is-shallow-repository") == "true"
}

func TestScanPRBitbucketUnshallows(t *testing.T) {
	dir, _ := shallowClone(t, "--no-single-branch")
	ctx := platform.Context{Platform: "bitbucket", Event: platform.EventPR, BaseRef: "main"}
	runScan(t, Options{Dir: dir, Ctx: ctx})
	if isShallow(t, dir) {
		t.Fatal("still shallow after a Bitbucket PR scan")
	}
}

func TestScanScheduleBitbucketUnshallows(t *testing.T) {
	dir, _ := shallowClone(t)
	runScan(t, Options{Dir: dir, Ctx: platform.Context{Platform: "bitbucket", Event: platform.EventSchedule}})
	if isShallow(t, dir) {
		t.Fatal("still shallow after a Bitbucket scheduled scan")
	}
}

// TestScanShallowFailsClosed: a PR or scheduled scan of a shallow clone would
// miss history, so outside Bitbucket (which cannot set the clone depth for a
// pipe) it is a configuration error naming the setting to change.
func TestScanShallowFailsClosed(t *testing.T) {
	cases := []platform.Context{
		{Platform: "github", Event: platform.EventPR, BaseRef: "main"},
		{Platform: "gitlab", Event: platform.EventPR, BaseRef: "main"},
		{Platform: "github", Event: platform.EventSchedule},
		{Platform: "gitlab", Event: platform.EventSchedule},
		{Platform: "local", Event: platform.EventSchedule},
	}
	for _, pc := range cases {
		dir, _ := shallowClone(t, "--no-single-branch")
		_, _, err := Run(context.Background(), Options{Dir: dir, Ctx: pc, Categories: allCats(), Now: fixedNow})
		if err == nil || !strings.Contains(err.Error(), "fetch-depth: 0") || !strings.Contains(err.Error(), "GIT_DEPTH: 0") {
			t.Errorf("%s %s: err = %v, want a shallow-clone error naming fetch-depth: 0 and GIT_DEPTH: 0", pc.Platform, pc.Event, err)
		}
		if !isShallow(t, dir) {
			t.Errorf("%s %s: clone was unshallowed", pc.Platform, pc.Event)
		}
	}
	// A push scan only reads the work tree: a shallow clone is fine.
	dir, _ := shallowClone(t)
	runScan(t, Options{Dir: dir, Ctx: platform.Context{Platform: "github", Event: platform.EventPush}})
}

// TestScanPRHeadIsBaseFailsClosed: with HEAD at (or behind) the base, a PR
// scan would compare the base with itself and pass; pull_request_target
// checks out the base by default.
func TestScanPRHeadIsBaseFailsClosed(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	first := r.Commit("one", "a.txt")
	r.Commit("two", "a.txt")
	_, _, err := Run(context.Background(), Options{Dir: r.Dir, Ctx: prCtx(), Categories: allCats(), Now: fixedNow})
	if err == nil || !strings.Contains(err.Error(), "HEAD is the base ref; check out the PR head") {
		t.Fatalf("HEAD == base: err = %v", err)
	}
	r.Git("checkout", "-q", "-b", "stale", first)
	_, _, err = Run(context.Background(), Options{Dir: r.Dir, Ctx: prCtx(), Categories: allCats(), Now: fixedNow})
	if err == nil || !strings.Contains(err.Error(), "HEAD is the base ref; check out the PR head") {
		t.Fatalf("HEAD behind base: err = %v", err)
	}
}

// Bitbucket clones with --single-branch --branch <pr branch> --depth N.
func TestScanPRBitbucketSingleBranchClone(t *testing.T) {
	isolate(t)
	origin := gitfixture.New(t)
	origin.Commit("one", "src/a.go")
	mainSHA := origin.Commit("two", "src/a.go")
	origin.Git("checkout", "-q", "-b", "feature")
	origin.Commit("feat", "src/b.go")
	origin.Git("checkout", "-q", "main")
	dst := filepath.Join(t.TempDir(), "clone")
	origin.Git("clone", "-q", "--single-branch", "--branch", "feature", "--depth", "1", "file://"+origin.Dir, dst)

	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: dst,
		head: []finding.Finding{fnd("opengrep", finding.CategorySAST, "old", "src/a.go")},
		base: []finding.Finding{fnd("opengrep", finding.CategorySAST, "old", "src/a.go")}}
	secrets := &fake{name: "gitleaks", cat: finding.CategorySecrets, headDir: dst}
	ctx := platform.Context{Platform: "bitbucket", Event: platform.EventPR, BaseRef: "main"}
	res, _ := runScan(t, Options{Dir: dst, Ctx: ctx, Scanners: []scanner.Scanner{secrets, sast}})

	if got := statusOf(t, res, "old"); got != finding.StatusExisting {
		t.Errorf("old: %q, want existing", got)
	}
	if lo := secrets.targets[0].LogOpts; lo != mainSHA+"..HEAD" {
		t.Errorf("LogOpts = %q, want %s..HEAD", lo, mainSHA)
	}
}

func TestScanPRDuplicateFindingIsNew(t *testing.T) {
	r, _ := prRepo(t, "", "")
	dup := fnd("opengrep", finding.CategorySAST, "dup", "src/a.go")
	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir,
		head: []finding.Finding{dup, dup, dup},
		base: []finding.Finding{dup}}
	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: prCtx(), Scanners: []scanner.Scanner{sast}})

	counts := map[finding.Status]int{}
	for _, f := range res.Findings {
		counts[f.Status]++
	}
	if counts[finding.StatusExisting] != 1 || counts[finding.StatusNew] != 2 {
		t.Errorf("statuses = %v, want 1 existing and 2 new", counts)
	}
}

func TestScanPRPolicyChangedIgnoresWorkingTree(t *testing.T) {
	r, _ := prRepo(t, "version: 1\nmode: enforce\n", "version: 1\nmode: enforce\n")
	if err := os.WriteFile(filepath.Join(r.Dir, ".shipguard.yaml"), []byte("version: 1\nmode: audit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: prCtx()})
	if res.PolicyChanged || res.PolicyDiff != "" {
		t.Errorf("changed=%v diff=%q; want the committed HEAD compared, not the working tree", res.PolicyChanged, res.PolicyDiff)
	}
}

func TestScanClearsStaleOutput(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	r.Commit("base", "src/a.go")
	out := filepath.Join(r.Dir, ".shipguard")
	for _, p := range []string{"findings.json", "policy.yaml", "raw/planted.json"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(out, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, p), []byte("planted"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A failing run (bad mode) must still leave no stale results behind.
	if _, _, err := Run(context.Background(), Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush}, Categories: allCats(), Mode: "warn"}); err == nil {
		t.Fatal("want error")
	}
	for _, p := range []string{"findings.json", "policy.yaml", "raw/planted.json"} {
		if _, err := os.Stat(filepath.Join(out, p)); !os.IsNotExist(err) {
			t.Errorf("%s survived: %v", p, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(out, "raw")); err != nil || !fi.IsDir() {
		t.Errorf("raw/ not recreated: %v", err)
	}
}

func TestScanReplacesSymlinkedOutDir(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	r.Commit("base", "src/a.go")
	victim := t.TempDir()
	keep := filepath.Join(victim, "raw", "keep.txt")
	if err := os.MkdirAll(filepath.Dir(keep), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(r.Dir, ".shipguard")); err != nil {
		t.Fatal(err)
	}
	runScan(t, Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush}})
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("symlink target was modified: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(r.Dir, ".shipguard")); err != nil || !fi.IsDir() {
		t.Errorf(".shipguard is not a real directory: %v", err)
	}
}

func TestScanScannerErrorRecorded(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	r.Commit("base", "src/a.go")
	bad := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir, headErr: errors.New("opengrep exited with code 2")}
	good := &fake{name: "osv-scanner", cat: finding.CategorySCA, headDir: r.Dir,
		head: []finding.Finding{fnd("osv-scanner", finding.CategorySCA, "cve", "go.mod")}}

	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: platform.Context{Platform: "local", Event: platform.EventPush}, Scanners: []scanner.Scanner{bad, good}})

	if run := runOf(t, res, "opengrep"); run.Status != "error" || run.Error != "opengrep exited with code 2" {
		t.Errorf("opengrep run = %+v", run)
	}
	if run := runOf(t, res, "osv-scanner"); run.Status != "ok" {
		t.Errorf("osv run = %+v", run)
	}
	if len(res.Findings) != 1 || res.Findings[0].ID != "cve" || res.Findings[0].Status != finding.StatusNone {
		t.Errorf("findings = %+v", res.Findings)
	}
}

func TestScanAppliesExcludes(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	commitFile(r, ".shipguard.yaml", "version: 1\npaths:\n  exclude: [\"vendor/\", \"**/*_test.go\"]\n")
	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir, head: []finding.Finding{
		fnd("opengrep", finding.CategorySAST, "keep", "src/a.go"),
		fnd("opengrep", finding.CategorySAST, "vendor", "vendor/x.go"),
		fnd("opengrep", finding.CategorySAST, "test", "src/a_test.go"),
		fnd("opengrep", finding.CategorySAST, "out", ".shipguard/raw/x.json"),
		fnd("opengrep", finding.CategorySAST, "sarif", ".shipguard/shipguard.sarif"),
		fnd("opengrep", finding.CategorySAST, "cache", ".shipguard-cache/db"),
		fnd("opengrep", finding.CategorySAST, "action", ".shipguard-action/a.sh"),
		fnd("opengrep", finding.CategorySAST, "git", ".git/config"),
		fnd("opengrep", finding.CategorySAST, "nm", "node_modules/a.js"),
		fnd("opengrep", finding.CategorySAST, "nested-nm", "web/node_modules/pkg/a.js"),
		fnd("opengrep", finding.CategorySAST, "own-dir", ".shipguard/app.py"),
	}}

	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush}, Scanners: []scanner.Scanner{sast}})

	var ids []string
	for _, f := range res.Findings {
		ids = append(ids, f.ID)
	}
	if !slices.Equal(ids, []string{"keep", "own-dir"}) {
		t.Errorf("findings = %v, want keep and own-dir (only shipguard's outputs are excluded in .shipguard/)", ids)
	}
	want := append([]string{"vendor/", "**/*_test.go"}, append(slices.Clone(RuntimeExclude), ".git/", "node_modules/", "**/node_modules/**")...)
	if got := sast.targets[0].Exclude; !slices.Equal(got, want) {
		t.Errorf("Target.Exclude = %q, want %q", got, want)
	}
}

// TestScanSecretsNotHiddenByExcludes: committed secrets are never hidden by
// shipguard's built-in excludes (R-I3); only shipguard's own run-time files
// are skipped in a directory scan, and nothing is skipped in a history scan.
func TestScanSecretsNotHiddenByExcludes(t *testing.T) {
	head := []finding.Finding{
		fnd("gitleaks", finding.CategorySecrets, "own-dir", ".shipguard/x.env"),
		fnd("gitleaks", finding.CategorySecrets, "nested-nm", "src/node_modules/cfg.js"),
		fnd("gitleaks", finding.CategorySecrets, "nm", "node_modules/cfg.js"),
		fnd("gitleaks", finding.CategorySecrets, "rules", ".shipguard/rules/r.yaml"),
		fnd("gitleaks", finding.CategorySecrets, "output", ".shipguard/findings.json"),
		fnd("gitleaks", finding.CategorySecrets, "raw", ".shipguard/raw/opengrep.json"),
		fnd("gitleaks", finding.CategorySecrets, "glreport", ".shipguard/gl-sast-report.json"),
		fnd("gitleaks", finding.CategorySecrets, "cache", ".shipguard-cache/trivy/db"),
		fnd("gitleaks", finding.CategorySecrets, "action", ".shipguard-action/rules/x.go"),
		fnd("gitleaks", finding.CategorySecrets, "user-excluded", "vendor/x.go"),
	}
	ids := func(res finding.Result) []string {
		var out []string
		for _, f := range res.Findings {
			out = append(out, f.ID)
		}
		return out
	}

	isolate(t)
	r := gitfixture.New(t)
	commitFile(r, ".shipguard.yaml", "version: 1\npaths:\n  exclude: [\"vendor/\"]\n")
	secrets := &fake{name: "gitleaks", cat: finding.CategorySecrets, headDir: r.Dir, head: head}
	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush}, Scanners: []scanner.Scanner{secrets}})
	if got, want := ids(res), []string{"own-dir", "nested-nm", "nm", "rules"}; !slices.Equal(got, want) {
		t.Errorf("push: findings = %v, want %v", got, want)
	}
	if got, want := secrets.targets[0].Exclude, append([]string{"vendor/"}, RuntimeExclude...); !slices.Equal(got, want) {
		t.Errorf("push: Target.Exclude = %q, want %q", got, want)
	}

	// A history scan reports committed content only: nothing is skipped but
	// the configured excludes.
	pr, _ := prRepo(t, "version: 1\npaths:\n  exclude: [\"vendor/\"]\n", "version: 1\npaths:\n  exclude: [\"vendor/\"]\n")
	secrets = &fake{name: "gitleaks", cat: finding.CategorySecrets, headDir: pr.Dir, head: head}
	res, _ = runScan(t, Options{Dir: pr.Dir, Ctx: prCtx(), Scanners: []scanner.Scanner{secrets}})
	if got := ids(res); len(got) != len(head)-1 || slices.Contains(got, "user-excluded") {
		t.Errorf("pr: findings = %v, want all but user-excluded", got)
	}
}

func TestScanTargets(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	commitFile(r, ".shipguard.yaml", "version: 1\ntimeouts:\n  per_scanner: 3m\nscanners:\n  sast:\n    rules: [p/x]\n    disable_rules: [r1]\n  sca:\n    licenses:\n      deny: [GPL-3.0]\n")
	secrets := &fake{name: "gitleaks", cat: finding.CategorySecrets, headDir: r.Dir}
	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir}

	runScan(t, Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventSchedule}, Scanners: []scanner.Scanner{secrets, sast}})

	st := secrets.targets[0]
	if !st.FullHistory || st.LogOpts != "" {
		t.Errorf("schedule secrets target = %+v, want FullHistory", st)
	}
	tt := sast.targets[0]
	if tt.Dir != r.Dir || tt.RawDir != filepath.Join(r.Dir, ".shipguard", "raw") || tt.CacheDir != filepath.Join(r.Dir, ".shipguard-cache") {
		t.Errorf("dirs = %q %q %q", tt.Dir, tt.RawDir, tt.CacheDir)
	}
	if tt.Timeout != 3*time.Minute || !slices.Equal(tt.Rules, []string{"p/x"}) || !slices.Equal(tt.DisableRules, []string{"r1"}) || !slices.Equal(tt.DenyLicenses, []string{"GPL-3.0"}) {
		t.Errorf("target = %+v", tt)
	}
	if tt.FullHistory || tt.LogOpts != "" {
		t.Errorf("non-secrets target carries history options: %+v", tt)
	}

	runScan(t, Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush}, Scanners: []scanner.Scanner{secrets}})
	if st := secrets.targets[1]; st.FullHistory || st.LogOpts != "" {
		t.Errorf("push secrets target = %+v, want a directory scan", st)
	}
}

func TestScanCategorySelection(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	commitFile(r, ".shipguard.yaml", "version: 1\nscanners:\n  iac:\n    enabled: false\n")
	secrets := &fake{name: "gitleaks", cat: finding.CategorySecrets, headDir: r.Dir}
	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir}
	iac := &fake{name: "trivy-config", cat: finding.CategoryIaC, headDir: r.Dir}

	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush},
		Categories: []finding.Category{finding.CategorySAST, finding.CategoryIaC},
		Scanners:   []scanner.Scanner{secrets, sast, iac}})

	if len(secrets.targets) != 0 || len(iac.targets) != 0 || len(sast.targets) != 1 {
		t.Errorf("calls: secrets=%d sast=%d iac=%d", len(secrets.targets), len(sast.targets), len(iac.targets))
	}
	if run := runOf(t, res, "trivy-config"); run.Status != "skipped" {
		t.Errorf("disabled iac run = %+v, want skipped", run)
	}
	for _, run := range res.Scanners {
		if run.Name == "gitleaks" {
			t.Errorf("unselected scanner recorded: %+v", run)
		}
	}
}

func TestScanModeOverride(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	commitFile(r, ".shipguard.yaml", "# keep me\nversion: 1\nmode: enforce\n")
	_, cfg := runScan(t, Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush}, Mode: "audit"})
	if cfg.Mode != "audit" {
		t.Errorf("mode = %q, want audit", cfg.Mode)
	}
	b, err := os.ReadFile(filepath.Join(r.Dir, ".shipguard", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := policy.Parse(b); err != nil || got.Mode != "audit" {
		t.Errorf("policy.yaml mode = %q, %v; want audit\n%s", got.Mode, err, b)
	}

	// The override also applies on top of the defaults when no file exists.
	r2 := gitfixture.New(t)
	r2.Commit("base", "a.go")
	runScan(t, Options{Dir: r2.Dir, Ctx: platform.Context{Event: platform.EventPush}, Mode: "audit"})
	b, _ = os.ReadFile(filepath.Join(r2.Dir, ".shipguard", "policy.yaml"))
	if got, err := policy.Parse(b); err != nil || got.Mode != "audit" {
		t.Errorf("defaults policy.yaml mode = %q, %v\n%s", got.Mode, err, b)
	}

	if _, _, err := Run(context.Background(), Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush}, Categories: allCats(), Mode: "warn"}); err == nil {
		t.Error("mode warn: want error")
	}
}

func TestScanInvalidConfigIsError(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	commitFile(r, ".shipguard.yaml", "version: 1\nbogus: true\n")
	_, _, err := Run(context.Background(), Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush}, Categories: allCats()})
	if !errors.Is(err, policy.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestScanWritesFindingsJSON(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	r.Commit("base", "src/a.go")
	sast := &fake{name: "opengrep", cat: finding.CategorySAST, headDir: r.Dir}
	pctx := platform.Context{Platform: "gitlab", Event: platform.EventPush, HeadSHA: "abc", Repo: "g/p"}
	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: pctx, Scanners: []scanner.Scanner{sast}, Version: "1.2.3"})

	got, err := finding.ReadResult(filepath.Join(r.Dir, ".shipguard", "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != 1 || got.ShipguardVersion != "1.2.3" || got.Findings == nil || len(got.Scanners) != 1 {
		t.Errorf("findings.json = %+v", got)
	}
	validFindingsJSON(t, r.Dir)
	var c platform.Context
	if err := json.Unmarshal(got.Context, &c); err != nil || c != pctx {
		t.Errorf("context = %s (%v), want %+v", got.Context, err, pctx)
	}
	var rc platform.Context
	if err := json.Unmarshal(res.Context, &rc); err != nil || rc != pctx || res.ShipguardVersion != "1.2.3" {
		t.Errorf("returned Result context = %s (%v), version %q", res.Context, err, res.ShipguardVersion)
	}
}

// validFindingsJSON checks the written findings.json against the published schema.
func validFindingsJSON(t *testing.T, dir string) {
	t.Helper()
	schema, err := jsonschema.NewCompiler().Compile("../../schema/findings.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, ".shipguard", "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	v, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(v); err != nil {
		t.Errorf("findings.json violates the schema: %v", err)
	}
}

func TestParseCategories(t *testing.T) {
	ok := map[string][]finding.Category{
		"":                     allCats(),
		"all":                  allCats(),
		"sast":                 {finding.CategorySAST},
		" sca , iac ":          {finding.CategorySCA, finding.CategoryIaC},
		"secrets,sast,sca,iac": allCats(),
	}
	for in, want := range ok {
		got, err := ParseCategories(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("ParseCategories(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{",", " , ", "sast,bogus", "all,sast", "SAST"} {
		if _, err := ParseCategories(in); !errors.Is(err, policy.ErrConfig) {
			t.Errorf("ParseCategories(%q) err = %v, want ErrConfig", in, err)
		}
	}
}

// TestScanExplicitConfigMissingFailsClosed: a config path the user named
// explicitly must exist; only the default .shipguard.yaml may be absent.
func TestScanExplicitConfigMissingFailsClosed(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	r.Commit("base", "src/a.go")
	push := platform.Context{Event: platform.EventPush}
	for _, p := range []string{"ci/shipguard.yaml", filepath.Join(r.Dir, "ci", "shipguard.yaml")} {
		_, _, err := Run(context.Background(), Options{Dir: r.Dir, ConfigPath: p, Ctx: push, Categories: allCats(), Now: fixedNow})
		if !errors.Is(err, policy.ErrConfig) || !strings.Contains(err.Error(), "ci/shipguard.yaml") {
			t.Errorf("push %s: err = %v, want a config error naming the file", p, err)
		}
	}
	// The default name, explicit or not, may be absent: defaults apply.
	for _, p := range []string{"", ".shipguard.yaml", "./.shipguard.yaml"} {
		res, _ := runScan(t, Options{Dir: r.Dir, ConfigPath: p, Ctx: push})
		if !res.PolicyDefaults {
			t.Errorf("config %q: PolicyDefaults = false, want true", p)
		}
	}

	// PR: missing at both head and base is an error; at either one is fine.
	pr, _ := prRepo(t, "", "")
	_, _, err := Run(context.Background(), Options{Dir: pr.Dir, ConfigPath: "ci/shipguard.yaml", Ctx: prCtx(), Categories: allCats(), Now: fixedNow})
	if !errors.Is(err, policy.ErrConfig) || !strings.Contains(err.Error(), "ci/shipguard.yaml") {
		t.Errorf("pr: err = %v, want a config error naming the file", err)
	}
	commitFile(pr, "ci/shipguard.yaml", "version: 1\n")
	res, _ := runScan(t, Options{Dir: pr.Dir, ConfigPath: "ci/shipguard.yaml", Ctx: prCtx()})
	if !res.PolicyChanged || !res.PolicyDefaults {
		t.Errorf("pr adding the config: changed=%v defaults=%v, want both (the base has none)", res.PolicyChanged, res.PolicyDefaults)
	}
}

func TestScanConfigFoundIsNotDefaults(t *testing.T) {
	isolate(t)
	r := gitfixture.New(t)
	commitFile(r, ".shipguard.yaml", "version: 1\n")
	res, _ := runScan(t, Options{Dir: r.Dir, Ctx: platform.Context{Event: platform.EventPush}})
	if res.PolicyDefaults {
		t.Error("PolicyDefaults = true with a config file present")
	}
	validFindingsJSON(t, r.Dir)
}
