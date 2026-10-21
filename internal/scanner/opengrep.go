package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// opengrepDefaultExcludes is opengrep 1.31.0's built-in default ignore list,
// observed by scanning a tree with and without --x-ignore-semgrepignore-files.
// shipguard passes it as --exclude (gitignore syntax: a name matches at any
// depth) unless scanners.sast.default_excludes is false. It is fixed in code,
// so a repository cannot change it.
var opengrepDefaultExcludes = []string{
	"vendor/", "build/", "dist/", "node_modules/",
	".venv/", ".env/", ".tox/", ".npm/", ".yarn/", "_build/",
	".hg/", ".svn/", "CVS/", "_darcs/",
	"test/", "tests/", "*_test.go", "*.min.js",
}

// OpengrepDefaultExcludes returns a copy of the fixed default exclude list.
func OpengrepDefaultExcludes() []string { return slices.Clone(opengrepDefaultExcludes) }

type opengrep struct {
	run          Runner
	builtinRules string
}

// NewOpengrep returns the SAST scanner backed by the opengrep binary.
// builtinRules is the path of the rules shipped with shipguard.
func NewOpengrep(run Runner, builtinRules string) Scanner {
	return &opengrep{run: run, builtinRules: builtinRules}
}

func (o *opengrep) Name() string               { return "opengrep" }
func (o *opengrep) Category() finding.Category { return finding.CategorySAST }

type opengrepReport struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Lines    string `json:"lines"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Level   string `json:"level"`
		Type    any    `json:"type"`
		RuleID  string `json:"rule_id"`
		Message string `json:"message"`
	} `json:"errors"`
}

func opengrepSeverity(s string) (finding.Severity, error) {
	switch s {
	case "ERROR":
		return finding.High, nil
	case "WARNING":
		return finding.Medium, nil
	case "INFO":
		return finding.Low, nil
	}
	return finding.Info, fmt.Errorf("unknown opengrep severity %q", s)
}

// ParseOpengrep converts an opengrep JSON report into findings. Entries in
// the report's errors array with level "error" make the whole parse fail.
func ParseOpengrep(raw []byte) ([]finding.Finding, error) {
	return parseOpengrep(raw, "")
}

func parseOpengrep(raw []byte, dir string) ([]finding.Finding, error) {
	return parseOpengrepRules(raw, dir, nil, nil)
}

// ruleIDs returns the ids declared in the rule files under the given config
// paths (files or directories). Unreadable or malformed files are skipped:
// opengrep itself reports invalid rule files.
func ruleIDs(dir string, configs []string) []string {
	var ids []string
	read := func(path string) {
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		var doc struct {
			Rules []struct {
				ID string `yaml:"id"`
			} `yaml:"rules"`
		}
		if yaml.Unmarshal(b, &doc) != nil {
			return
		}
		for _, r := range doc.Rules {
			if r.ID != "" {
				ids = append(ids, r.ID)
			}
		}
	}
	for _, c := range configs {
		if !filepath.IsAbs(c) {
			c = filepath.Join(dir, c)
		}
		st, err := os.Stat(c)
		if err != nil {
			continue
		}
		if !st.IsDir() {
			read(c)
			continue
		}
		_ = filepath.WalkDir(c, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
				read(p)
			}
			return nil
		})
	}
	sort.Slice(ids, func(i, j int) bool { return len(ids[i]) > len(ids[j]) })
	return ids
}

// normalizeCheckID undoes the prefix opengrep adds to every check_id: the
// dotted path of the directory that holds the rule file (for example
// "opt.shipguard.rules.go." for --config /opt/shipguard/rules). The rule's own
// id is recovered from the known ids; the last "shipguard." segment is the
// fallback for built-in rules.
func normalizeCheckID(id string, known []string) string {
	for _, k := range known {
		if id == k || strings.HasSuffix(id, "."+k) {
			return k
		}
	}
	if i := strings.LastIndex(id, "shipguard."); i > 0 && id[i-1] == '.' {
		return id[i:]
	}
	return id
}

func parseOpengrepRules(raw []byte, dir string, known, disabled []string) ([]finding.Finding, error) {
	var rep opengrepReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("parse opengrep report: %w", err)
	}
	for _, e := range rep.Errors {
		if e.Level == "error" {
			return nil, fmt.Errorf("opengrep reported an error (type %q, rule %q)", errType(e.Type), e.RuleID)
		}
	}
	out := make([]finding.Finding, 0, len(rep.Results))
	for _, r := range rep.Results {
		sev, err := opengrepSeverity(r.Extra.Severity)
		if err != nil {
			return nil, fmt.Errorf("opengrep result %s: %w", r.CheckID, err)
		}
		id := normalizeCheckID(r.CheckID, known)
		if slices.Contains(disabled, id) {
			continue
		}
		file := relFile(r.Path, dir)
		out = append(out, finding.Finding{
			ID:          id,
			Scanner:     "opengrep",
			Category:    finding.CategorySAST,
			Severity:    sev,
			File:        file,
			Line:        r.Start.Line,
			Message:     r.Extra.Message,
			Fingerprint: finding.Fingerprint(id, file, finding.NormalizeSnippet(r.Extra.Lines)),
		})
	}
	return out, nil
}

// errType returns the error type when it is a plain string. The free-text
// message is never used: it can embed source or pattern text.
func errType(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return "unknown"
}

func (o *opengrep) args(t Target, output string) []string {
	a := []string{"scan", "--json", "--output", output, "--config", o.builtinRules}
	for _, r := range t.Rules {
		a = append(a, "--config", r)
	}
	// --exclude-rule is not used: it needs the prefixed check_id opengrep
	// derives from the config path, so disabled rules are filtered by bare
	// id after parsing.
	for _, e := range t.Exclude {
		a = append(a, "--exclude", e)
	}
	if t.SASTDefaultExcludes {
		for _, e := range opengrepDefaultExcludes {
			a = append(a, "--exclude", e)
		}
	}
	// Policy lives only in .shipguard.yaml: nosem/nosemgrep/noopengrep
	// comments and .semgrepignore files in the repository are not honoured.
	// --x-ignore-semgrepignore-files is opengrep's (v1.31.0) only switch for
	// that; it also drops opengrep's built-in default ignore list, which
	// opengrepDefaultExcludes restores (scanners.sast.default_excludes).
	// .gitignore cannot hide tracked files.
	a = append(a, "--disable-nosem", "--x-ignore-semgrepignore-files")
	// opengrep has no --metrics flag (v1.31.0) and sends no telemetry.
	return append(a, ".")
}

func (o *opengrep) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	ctx, cancel := withTimeout(ctx, t)
	defer cancel()

	// The verbatim report contains source lines, so it lives outside Dir and
	// RawDir and is deleted; only normalized findings are kept.
	output, err := tempReport(t, "opengrep")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(output) }()

	// Stderr is dropped: it can echo source code.
	_, _, code, err := o.run(ctx, t.Dir, "opengrep", o.args(t, output)...)
	if err != nil {
		return nil, fmt.Errorf("opengrep: %w", err)
	}
	if code != 0 && code != 1 {
		return nil, fmt.Errorf("opengrep exited with code %d", code)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		return nil, fmt.Errorf("read opengrep output: %w", err)
	}
	if err := checkReport("opengrep", raw, code); err != nil {
		return nil, err
	}
	known := ruleIDs(t.Dir, append([]string{o.builtinRules}, t.Rules...))
	fs, err := parseOpengrepRules(raw, t.Dir, known, t.DisableRules)
	if err != nil {
		return nil, err
	}
	if t.RawDir != "" {
		if err := writeRaw(t.RawDir, "opengrep", fs); err != nil {
			return nil, err
		}
	}
	return fs, nil
}
