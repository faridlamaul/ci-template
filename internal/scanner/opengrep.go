package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/faridlamaul/shipguard/internal/finding"
)

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
	var rep opengrepReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("parse opengrep report: %w", err)
	}
	for _, e := range rep.Errors {
		if e.Level == "error" {
			return nil, fmt.Errorf("opengrep reported an error (rule %q): %s", e.RuleID, strings.TrimSpace(firstLine(e.Message)))
		}
	}
	out := make([]finding.Finding, 0, len(rep.Results))
	for _, r := range rep.Results {
		sev, err := opengrepSeverity(r.Extra.Severity)
		if err != nil {
			return nil, fmt.Errorf("opengrep result %s: %w", r.CheckID, err)
		}
		file := relFile(r.Path, dir)
		out = append(out, finding.Finding{
			ID:          r.CheckID,
			Scanner:     "opengrep",
			Category:    finding.CategorySAST,
			Severity:    sev,
			File:        file,
			Line:        r.Start.Line,
			Message:     r.Extra.Message,
			Fingerprint: finding.Fingerprint(r.CheckID, file, finding.NormalizeSnippet(r.Extra.Lines)),
		})
	}
	return out, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func (o *opengrep) args(t Target, output string) []string {
	a := []string{"scan", "--json", "--output", output, "--config", o.builtinRules}
	for _, r := range t.Rules {
		a = append(a, "--config", r)
	}
	for _, r := range t.DisableRules {
		a = append(a, "--exclude-rule", r)
	}
	for _, e := range t.Exclude {
		a = append(a, "--exclude", e)
	}
	// opengrep has no --metrics flag (v1.31.0) and sends no telemetry.
	return append(a, ".")
}

func (o *opengrep) Scan(ctx context.Context, t Target) ([]finding.Finding, error) {
	ctx, cancel := withTimeout(ctx, t)
	defer cancel()

	rawDir := t.RawDir
	if rawDir == "" {
		d, err := os.MkdirTemp("", "shipguard-opengrep-*")
		if err != nil {
			return nil, fmt.Errorf("create opengrep output dir: %w", err)
		}
		defer os.RemoveAll(d)
		rawDir = d
	} else if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return nil, fmt.Errorf("create raw dir: %w", err)
	}
	output := filepath.Join(rawDir, "opengrep.json")

	// A stale file must never be mistaken for this run's output.
	if err := os.Remove(output); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale opengrep output: %w", err)
	}

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
	return parseOpengrep(raw, t.Dir)
}
