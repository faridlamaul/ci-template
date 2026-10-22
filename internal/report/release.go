package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/release"
)

// releaseSummaryMax caps the findings rows in the release summary.
const releaseSummaryMax = 50

// releaseJSON is the shape of result.json.
type releaseJSON struct {
	Released    bool          `json:"released"`
	Tag         string        `json:"tag"`
	Version     string        `json:"version"`
	Image       string        `json:"image"`
	ImageDigest string        `json:"image_digest"`
	Steps       []releaseStep `json:"steps"`
}

type releaseStep struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// ReleaseSummary renders the release result as Markdown: the steps, what was
// released and, when a step was blocked, the image findings.
func ReleaseSummary(r release.Result) string {
	var b strings.Builder
	b.WriteString("## shipguard release\n\n")
	b.WriteString("| Step | Status | Duration | Reason |\n|---|---|---|---|\n")
	blocked := false
	for _, s := range r.Steps {
		blocked = blocked || s.Status == "blocked"
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", cell(s.Name), cell(s.Status), s.Duration.Round(10*time.Millisecond), cell(s.Reason))
	}
	b.WriteString("\n")
	switch {
	case r.Released:
		fmt.Fprintf(&b, "Released **%s**.\n\n", cell(r.Tag))
	case r.Version == "":
		b.WriteString("Nothing to release.\n\n")
	}
	if r.Image != "" && r.Tag != "" {
		fmt.Fprintf(&b, "- Image: `%s:%s`\n", r.Image, r.Tag)
	}
	if r.ImageDigest != "" {
		fmt.Fprintf(&b, "- Digest: `%s`\n", r.ImageDigest)
	}
	if r.Image != "" && r.Tag != "" || r.ImageDigest != "" {
		b.WriteString("\n")
	}
	if blocked && len(r.Blocking) > 0 {
		fs := append([]finding.Finding(nil), r.Blocking...)
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
		b.WriteString("### Blocking image findings\n\nNothing was pushed. Highest severity first.\n\n")
		b.WriteString("| Severity | ID | Location | Message |\n|---|---|---|---|\n")
		for i, f := range fs {
			if i >= releaseSummaryMax {
				fmt.Fprintf(&b, "\n…and %d more findings in .shipguard/release/image-findings.json\n", len(fs)-i)
				break
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", f.Severity, cell(f.ID), cell(f.File), cell(f.Message))
		}
	}
	return b.String()
}

// WriteRelease writes .shipguard/release/{result.json,summary.md,image-findings.json}.
// The image findings are kept apart from findings.json so they never reach
// the SARIF, GitLab or Bitbucket reporters or the annotations.
func WriteRelease(dir string, r release.Result) error {
	base := filepath.Join(dir, outDir, "release")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return fmt.Errorf("create release output dir: %w", err)
	}
	rj := releaseJSON{Released: r.Released, Tag: r.Tag, Version: r.Version, Image: r.Image, ImageDigest: r.ImageDigest, Steps: []releaseStep{}}
	for _, s := range r.Steps {
		rj.Steps = append(rj.Steps, releaseStep{s.Name, s.Status, s.Reason, s.Duration.Milliseconds()})
	}
	js, err := json.MarshalIndent(rj, "", "  ")
	if err != nil {
		return fmt.Errorf("encode result.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(base, "result.json"), append(js, '\n'), 0o644); err != nil {
		return fmt.Errorf("write result.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(base, "summary.md"), []byte(ReleaseSummary(r)), 0o644); err != nil {
		return fmt.Errorf("write summary.md: %w", err)
	}
	fr := finding.Result{SchemaVersion: 1, Findings: r.Findings}
	if err := finding.WriteResult(filepath.Join(base, "image-findings.json"), fr); err != nil {
		return fmt.Errorf("write image-findings.json: %w", err)
	}
	return nil
}

// ReleaseOutputs appends released, tag, version, image and image_digest to
// $GITHUB_OUTPUT and the summary to $GITHUB_STEP_SUMMARY, when they are set.
func ReleaseOutputs(r release.Result, getenv func(string) string) error {
	if p := getenv("GITHUB_OUTPUT"); p != "" {
		for _, v := range []string{r.Tag, r.Version, r.Image, r.ImageDigest} {
			if strings.ContainsAny(v, "\r\n") {
				return fmt.Errorf("release output value contains a newline: %q", v)
			}
		}
		lines := fmt.Sprintf("released=%t\ntag=%s\nversion=%s\nimage=%s\nimage_digest=%s\n",
			r.Released, r.Tag, r.Version, r.Image, r.ImageDigest)
		if err := appendFile(p, lines); err != nil {
			return err
		}
	}
	if p := getenv("GITHUB_STEP_SUMMARY"); p != "" {
		return appendFile(p, ReleaseSummary(r))
	}
	return nil
}
