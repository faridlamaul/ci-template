// Package scan runs the configured scanners against the repository and, on a
// PR/MR, against the base ref to mark each finding new or existing.
package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/gitx"
	"github.com/faridlamaul/shipguard/internal/platform"
	"github.com/faridlamaul/shipguard/internal/policy"
	"github.com/faridlamaul/shipguard/internal/scanner"
)

// Paths inside the repository.
const (
	OutDir        = ".shipguard"       // results: findings.json, policy.yaml, raw/
	CacheDir      = ".shipguard-cache" // scanner DB cache
	DefaultConfig = ".shipguard.yaml"
	SchemaVersion = 1
)

// RuntimeExclude lists what shipguard itself writes or checks out into the
// repository at run time: its outputs in .shipguard/ (not the whole
// directory, which may hold consumer rules), the scanner cache and the
// action checkout. It is never scanned.
var RuntimeExclude = []string{
	OutDir + "/findings.json", OutDir + "/policy.yaml", OutDir + "/raw/", OutDir + "/summary.md",
	OutDir + "/gate.env", OutDir + "/*.sarif", OutDir + "/gl-*.json",
	CacheDir + "/", ".shipguard-action/",
}

// AlwaysExclude lists the paths the SAST, SCA and IaC scanners never scan,
// whatever the config says. Secrets use only RuntimeExclude, and only in a
// directory scan, so a committed secret is never hidden.
var AlwaysExclude = append(slices.Clone(RuntimeExclude), ".git/", "node_modules/", "**/node_modules/**")

// defaultsYAML is written to policy.yaml when the repository has no config;
// policy.Parse turns it into policy.Defaults().
const defaultsYAML = "# No .shipguard.yaml at this revision: built-in defaults apply.\nversion: 1\n"

var allCategories = []finding.Category{finding.CategorySecrets, finding.CategorySAST, finding.CategorySCA, finding.CategoryIaC}

// Options configures Run.
type Options struct {
	Dir        string // repository root
	ConfigPath string // relative to Dir (default .shipguard.yaml)
	Categories []finding.Category
	Ctx        platform.Context
	Scanners   []scanner.Scanner
	Now        func() time.Time
	Version    string // shipguard version recorded in findings.json
	Mode       string // --mode override: "", enforce or audit
}

// ParseCategories parses the --scanners value: empty or "all", or a comma
// list of secrets, sast, sca and iac.
func ParseCategories(s string) ([]finding.Category, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return slices.Clone(allCategories), nil
	}
	var out []finding.Category
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		c := finding.Category(p)
		if !slices.Contains(allCategories, c) {
			return nil, fmt.Errorf("%w: --scanners: unknown scanner %q (want all or a comma list of secrets, sast, sca, iac)", policy.ErrConfig, p)
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: --scanners: empty scanner list", policy.ErrConfig)
	}
	return out, nil
}

// headResult is one scanner's outcome on the head tree.
type headResult struct {
	s        scanner.Scanner
	t        scanner.Target
	run      finding.ScannerRun
	findings []finding.Finding
}

// Run loads the effective config, runs the selected scanners and writes
// .shipguard/findings.json, .shipguard/policy.yaml and .shipguard/raw/. Scanner
// failures are recorded in the result; the error return is reserved for
// config, base-resolution and output errors.
func Run(ctx context.Context, o Options) (finding.Result, policy.Config, error) {
	out := filepath.Join(o.Dir, OutDir)
	rawDir := filepath.Join(out, "raw")
	if err := resetOutput(out); err != nil {
		return finding.Result{}, policy.Config{}, err
	}
	if o.Mode != "" && o.Mode != "enforce" && o.Mode != "audit" {
		return finding.Result{}, policy.Config{}, fmt.Errorf("%w: --mode must be enforce or audit, got %q", policy.ErrConfig, o.Mode)
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	pr := o.Ctx.Event == platform.EventPR

	if pr || o.Ctx.Event == platform.EventSchedule {
		if err := fullHistory(o.Dir, o.Ctx.Platform); err != nil {
			return finding.Result{}, policy.Config{}, err
		}
	}
	var baseSHA string
	if pr {
		var err error
		if baseSHA, err = gitx.ResolveRef(o.Dir, o.Ctx.BaseRef); err != nil {
			return finding.Result{}, policy.Config{}, err
		}
		// pull_request_target, for one, checks out the base by default:
		// the scan would compare the base with itself and pass.
		behind, err := gitx.IsAncestor(o.Dir, "HEAD", baseSHA)
		if err != nil {
			return finding.Result{}, policy.Config{}, err
		}
		if behind {
			return finding.Result{}, policy.Config{}, fmt.Errorf("%w: HEAD is the base ref; check out the PR head (HEAD is %s or an ancestor of it)", policy.ErrConfig, o.Ctx.BaseRef)
		}
	}

	ec, err := effectiveConfig(o.Dir, o.ConfigPath, baseSHA, o.Mode)
	if err != nil {
		return finding.Result{}, policy.Config{}, err
	}
	cfg := ec.cfg

	if err := os.WriteFile(filepath.Join(out, "policy.yaml"), ec.bytes, 0o644); err != nil {
		return finding.Result{}, policy.Config{}, fmt.Errorf("write effective policy: %w", err)
	}

	base := &baseTree{dir: o.Dir, sha: baseSHA}
	defer base.close()
	rules := cfg.Scanners.SAST.Rules
	if slices.Contains(o.Categories, finding.CategorySAST) && cfg.Scanners.SAST.Enabled {
		if rules, err = resolveRules(o.Dir, rules, pr, base); err != nil {
			return finding.Result{}, policy.Config{}, err
		}
	}

	head := scanner.Target{
		Dir:                 o.Dir,
		RawDir:              rawDir,
		CacheDir:            filepath.Join(o.Dir, CacheDir),
		Exclude:             append(slices.Clone(cfg.Paths.Exclude), AlwaysExclude...),
		Timeout:             cfg.Timeouts.PerScanner,
		Rules:               rules,
		DisableRules:        cfg.Scanners.SAST.DisableRules,
		SASTDefaultExcludes: cfg.Scanners.SAST.DefaultExcludes,
		DenyLicenses:        cfg.Scanners.SCA.Licenses.Deny,
	}

	var results []headResult
	for _, s := range o.Scanners {
		cat := s.Category()
		if !slices.Contains(o.Categories, cat) {
			continue
		}
		hr := headResult{s: s, run: finding.ScannerRun{Name: s.Name(), Category: cat}}
		if !enabled(cfg, cat) {
			hr.run.Status = finding.RunStatusSkipped
			results = append(results, hr)
			continue
		}
		t := head
		if cat == finding.CategorySecrets {
			// A history scan reports committed content only, so only the
			// configured excludes apply; a directory scan also skips
			// shipguard's run-time files.
			t.Exclude = slices.Clone(cfg.Paths.Exclude)
			switch {
			case pr:
				t.LogOpts = baseSHA + "..HEAD"
			case o.Ctx.Event == platform.EventSchedule:
				t.FullHistory = true
			default:
				t.Exclude = append(t.Exclude, RuntimeExclude...)
			}
		}
		hr.t = t
		start := now()
		fs, err := s.Scan(ctx, t)
		hr.run.DurationMS = now().Sub(start).Milliseconds()
		if err != nil {
			hr.run.Status, hr.run.Error = finding.RunStatusError, err.Error()
		} else {
			hr.run.Status, hr.findings = finding.RunStatusOK, fs
		}
		status := finding.StatusNone
		if pr {
			status = finding.StatusNew
		}
		for i := range hr.findings {
			hr.findings[i].Status = status
		}
		results = append(results, hr)
	}

	if pr {
		if err := markExisting(ctx, base, results, now); err != nil {
			return finding.Result{}, policy.Config{}, err
		}
	}

	res := finding.Result{
		SchemaVersion:    SchemaVersion,
		ShipguardVersion: o.Version,
		Scanners:         []finding.ScannerRun{},
		PolicyChanged:    ec.changed,
		PolicyDiff:       ec.diff,
		PolicyDefaults:   ec.defaults,
	}
	if res.Context, err = json.Marshal(o.Ctx); err != nil {
		return finding.Result{}, policy.Config{}, fmt.Errorf("encode context: %w", err)
	}
	res.Findings = []finding.Finding{}
	for _, hr := range results {
		res.Scanners = append(res.Scanners, hr.run)
		res.Findings = append(res.Findings, finding.FilterPaths(hr.findings, hr.t.Exclude)...)
	}
	if err := finding.WriteResult(filepath.Join(out, "findings.json"), res); err != nil {
		return finding.Result{}, policy.Config{}, err
	}
	return res, cfg, nil
}

// fullHistory makes sure a PR or scheduled scan sees the whole history: a
// shallow clone would hide commits from the secrets scan and may lack the
// base. Bitbucket pipes cannot set the clone depth, so there it is
// unshallowed; elsewhere it is a configuration error.
func fullHistory(dir, plat string) error {
	shallow, err := gitx.IsShallow(dir)
	if err != nil || !shallow {
		return err
	}
	if plat == "bitbucket" {
		return gitx.Unshallow(dir)
	}
	return fmt.Errorf("%w: shallow clone: PR and scheduled scans need the full git history; "+
		"set fetch-depth: 0 on actions/checkout (GitHub) or GIT_DEPTH: 0 (GitLab)", policy.ErrConfig)
}

// baseTree is the base revision checked out in a temporary worktree, created
// on first use and shared by everything that reads the base.
type baseTree struct {
	dir, sha string
	wt       string
	err      error
	cleanup  func()
}

func (b *baseTree) path() (string, error) {
	if b.wt == "" && b.err == nil {
		b.wt, b.cleanup, b.err = gitx.Worktree(b.dir, b.sha)
	}
	return b.wt, b.err
}

func (b *baseTree) close() {
	if b.cleanup != nil {
		b.cleanup()
	}
}

// resolveRules turns the consumer rule paths into absolute paths and checks
// that they exist; URLs are kept as they are. Rules are policy, so on a PR
// relative paths, and absolute ones inside the repository, are read from the
// base worktree, never from the PR head.
func resolveRules(dir string, rules []string, pr bool, base *baseTree) ([]string, error) {
	var out []string
	for _, r := range rules {
		if strings.Contains(r, "://") {
			out = append(out, r)
			continue
		}
		p, inRepo := r, !filepath.IsAbs(r)
		if !inRepo {
			if rel, err := filepath.Rel(dir, r); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				p, inRepo = rel, true
			}
		}
		where := ""
		if inRepo {
			root := dir
			if pr {
				wt, err := base.path()
				if err != nil {
					return nil, fmt.Errorf("read sast rules at base: %w", err)
				}
				root, where = wt, " at the base ref"
			}
			p = filepath.Join(root, p)
		}
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("%w: scanners.sast.rules: %s not found%s", policy.ErrConfig, r, where)
		}
		out = append(out, p)
	}
	return out, nil
}

// markExisting scans the base revision in a worktree with every head scanner
// that succeeded (except secrets, whose log range is already PR-only) and
// marks head findings whose fingerprint the base also has as existing, at
// most as many per fingerprint as the base has. A base
// failure turns the head run into an error and leaves its findings new.
func markExisting(ctx context.Context, base *baseTree, results []headResult, now func() time.Time) error {
	baseRaw, err := os.MkdirTemp("", "shipguard-base-raw-*")
	if err != nil {
		return fmt.Errorf("create base raw dir: %w", err)
	}
	defer os.RemoveAll(baseRaw)

	for i := range results {
		hr := &results[i]
		if hr.run.Status != finding.RunStatusOK || hr.run.Category == finding.CategorySecrets || len(hr.findings) == 0 {
			continue
		}
		wt, err := base.path()
		if err != nil {
			hr.run.Status, hr.run.Error = finding.RunStatusError, "base scan failed: "+err.Error()
			continue
		}
		t := hr.t
		t.Dir, t.RawDir = wt, baseRaw
		start := now()
		baseFs, err := hr.s.Scan(ctx, t)
		hr.run.DurationMS += now().Sub(start).Milliseconds()
		if err != nil {
			hr.run.Status, hr.run.Error = finding.RunStatusError, "base scan failed: "+err.Error()
			continue
		}
		// Multiset match: a PR that adds another copy of an existing
		// finding gets the extra copy marked new.
		left := make(map[string]int, len(baseFs))
		for _, f := range baseFs {
			left[f.Fingerprint]++
		}
		for j := range hr.findings {
			if fp := hr.findings[j].Fingerprint; left[fp] > 0 {
				left[fp]--
				hr.findings[j].Status = finding.StatusExisting
			}
		}
	}
	return nil
}

func enabled(cfg policy.Config, c finding.Category) bool {
	switch c {
	case finding.CategorySecrets:
		return cfg.Scanners.Secrets.Enabled
	case finding.CategorySAST:
		return cfg.Scanners.SAST.Enabled
	case finding.CategorySCA:
		return cfg.Scanners.SCA.Enabled
	case finding.CategoryIaC:
		return cfg.Scanners.IaC.Enabled
	}
	return false
}

// effective is the config the gate will use, with the bytes written to
// .shipguard/policy.yaml (cfg is parsed from exactly those bytes).
type effective struct {
	cfg      policy.Config
	bytes    []byte
	changed  bool
	diff     string
	defaults bool // no config file at the revision used
}

// effectiveConfig picks the base revision's config on a PR (baseSHA != "")
// and the working tree's otherwise, applies the mode override, and parses it.
// Only the default .shipguard.yaml may be absent; a config path named
// explicitly must exist (on a PR at the head or the base).
func effectiveConfig(dir, configPath, baseSHA, mode string) (effective, error) {
	var e effective
	rel, err := configRel(dir, configPath)
	if err != nil {
		return e, err
	}
	headBytes, headOK, err := readFile(filepath.Join(dir, rel))
	if err != nil {
		return e, err
	}
	data, ok, source := headBytes, headOK, rel
	found := headOK
	if baseSHA != "" {
		slash := filepath.ToSlash(rel)
		baseBytes, baseOK, err := gitx.Show(dir, baseSHA, slash)
		if err != nil {
			return e, fmt.Errorf("read base config: %w", err)
		}
		// Compare committed HEAD, the same revisions PolicyDiff shows.
		commitBytes, commitOK, err := gitx.Show(dir, "HEAD", slash)
		if err != nil {
			return e, fmt.Errorf("read head config: %w", err)
		}
		data, ok, source = baseBytes, baseOK, rel+" at base "+baseSHA
		found = found || commitOK || baseOK
		if commitOK != baseOK || !bytes.Equal(commitBytes, baseBytes) {
			e.changed = true
			if e.diff, err = gitx.Diff(dir, baseSHA, "HEAD", slash); err != nil {
				return e, err
			}
		}
	}
	if !found && rel != DefaultConfig {
		return e, fmt.Errorf("%w: config %s not found", policy.ErrConfig, filepath.ToSlash(rel))
	}
	if !ok {
		data = []byte(defaultsYAML)
		e.defaults = true
	}
	if mode != "" {
		if data, err = setMode(data, mode); err != nil {
			return e, fmt.Errorf("%s: %w", source, err)
		}
	}
	if e.cfg, err = policy.Parse(data); err != nil {
		return e, fmt.Errorf("%s: %w", source, err)
	}
	e.bytes = data
	return e, nil
}

// outputs are the files and directories shipguard writes into OutDir (glob
// patterns); anything else there, such as consumer rules, is left alone.
var outputs = []string{"findings.json", "policy.yaml", "raw", "summary.md", "gate.env", "*.sarif", "gl-*.json"}

// ResetOutputs removes every output a previous run (or a commit) left in the
// repository's OutDir; see resetOutput. Callers run it before validating
// anything, so a failed run never leaves stale results behind.
func ResetOutputs(dir string) error { return resetOutput(filepath.Join(dir, OutDir)) }

// resetOutput removes results a previous run (or a commit) left in out, so
// nothing stale or planted is read as this run's output, and recreates raw/.
// A symlink or file at out is replaced by a real directory.
func resetOutput(out string) error {
	if fi, err := os.Lstat(out); err == nil && !fi.IsDir() {
		if err := os.Remove(out); err != nil {
			return fmt.Errorf("reset output dir: %w", err)
		}
	}
	for _, pat := range outputs {
		matches, err := filepath.Glob(filepath.Join(out, pat))
		if err != nil {
			return fmt.Errorf("reset output dir: %w", err)
		}
		for _, p := range matches {
			if err := os.RemoveAll(p); err != nil {
				return fmt.Errorf("reset output dir: %w", err)
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(out, "raw"), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	return nil
}

// configRel returns the config path relative to the repository root.
func configRel(dir, p string) (string, error) {
	if p == "" {
		p = DefaultConfig
	}
	if filepath.IsAbs(p) {
		r, err := filepath.Rel(dir, p)
		if err != nil {
			return "", fmt.Errorf("%w: config %s: %v", policy.ErrConfig, p, err)
		}
		p = r
	}
	p = filepath.Clean(p)
	if p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: config %s must be inside the repository", policy.ErrConfig, p)
	}
	return p, nil
}

func readFile(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read config: %w", err)
	}
	return b, true, nil
}

// setMode sets the top-level mode key of a YAML config document.
func setMode(data []byte, mode string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", policy.ErrConfig, err)
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: config must be a mapping", policy.ErrConfig)
	}
	val := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: mode}
	set := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "mode" {
			root.Content[i+1] = val
			set = true
		}
	}
	if !set {
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "mode"}, val)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return buf.Bytes(), nil
}
