package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

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
			return nil, fmt.Errorf("opengrep reported an error (type %q, rule %q)", errType(e.Type), e.RuleID)
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

	// The verbatim report contains source lines, so it lives outside Dir and
	// RawDir and is deleted; only normalized findings are kept.
	output, err := tempReport(t, "opengrep")
	if err != nil {
		return nil, err
	}
	defer os.Remove(output)

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
	fs, err := parseOpengrep(raw, t.Dir)
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
