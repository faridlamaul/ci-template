// Package report renders the gate summary and CI outputs.
package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/faridlamaul/shipguard/internal/policy"
)

// outDir is the shipguard output directory, relative to the repository.
const outDir = ".shipguard"

// WriteOutputs writes .shipguard/gate.env and, when $GITHUB_OUTPUT is set,
// appends result, new_findings and total_findings to that file.
func WriteOutputs(dir string, d policy.Decision, getenv func(string) string) error {
	out := filepath.Join(dir, outDir)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	env := fmt.Sprintf("SHIPGUARD_RESULT=%s\nSHIPGUARD_NEW_FINDINGS=%d\nSHIPGUARD_TOTAL_FINDINGS=%d\n",
		d.Result, d.New, d.Total)
	if err := os.WriteFile(filepath.Join(out, "gate.env"), []byte(env), 0o644); err != nil {
		return fmt.Errorf("write gate.env: %w", err)
	}
	gh := getenv("GITHUB_OUTPUT")
	if gh == "" {
		return nil
	}
	lines := fmt.Sprintf("result=%s\nnew_findings=%d\ntotal_findings=%d\n", d.Result, d.New, d.Total)
	return appendFile(gh, lines)
}

func appendFile(path, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

// AppendStepSummary appends content to the file at path (a CI step summary).
func AppendStepSummary(path, content string) error { return appendFile(path, content) }
