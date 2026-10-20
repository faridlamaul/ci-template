package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// gitlabSchemaVersion is the GitLab security-report-schemas tag the reports
// conform to (see testdata/gitlab/SOURCE).
const gitlabSchemaVersion = "15.2.5"

// gitlabNoCommit is the placeholder commit sha the secret-detection schema
// requires; shipguard findings do not carry commit information.
const gitlabNoCommit = "0000000000000000000000000000000000000000"

const gitlabTimeFormat = "2006-01-02T15:04:05"

type glReport struct {
	Version         string   `json:"version"`
	Scan            glScan   `json:"scan"`
	Vulnerabilities []glVuln `json:"vulnerabilities"`
}

type glScan struct {
	Analyzer  glTool `json:"analyzer"`
	Scanner   glTool `json:"scanner"`
	Type      string `json:"type"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Status    string `json:"status"`
}

type glTool struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Vendor  glVendor `json:"vendor"`
}

type glVendor struct {
	Name string `json:"name"`
}

type glVuln struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Severity    string         `json:"severity"`
	Solution    string         `json:"solution,omitempty"`
	Identifiers []glIdentifier `json:"identifiers"`
	Location    glLocation     `json:"location"`
}

type glIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type glLocation struct {
	File       string        `json:"file"`
	StartLine  int           `json:"start_line,omitempty"`
	Commit     *glCommit     `json:"commit,omitempty"`
	Dependency *glDependency `json:"dependency,omitempty"`
}

type glCommit struct {
	SHA string `json:"sha"`
}

type glDependency struct {
	Package glPackage `json:"package"`
	Version string    `json:"version,omitempty"`
}

type glPackage struct {
	Name string `json:"name"`
}

type glKind struct {
	file     string
	scanType string
	covers   func(finding.Category) bool
}

var glKinds = []glKind{
	{"gl-secret-detection-report.json", "secret_detection", func(c finding.Category) bool { return c == finding.CategorySecrets }},
	{"gl-sast-report.json", "sast", func(c finding.Category) bool { return c == finding.CategorySAST || c == finding.CategoryIaC }},
	{"gl-dependency-scanning-report.json", "dependency_scanning", func(c finding.Category) bool { return c == finding.CategorySCA }},
}

// WriteGitLab writes the three GitLab security reports (secret detection, SAST
// and dependency scanning) into dir. All three are written even when empty.
// IaC findings go to the SAST report; SCA findings, including licenses with
// severity of at least low, go to the dependency scanning report.
func WriteGitLab(dir string, r finding.Result, version string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create gitlab report dir: %w", err)
	}
	ts := now.UTC().Format(gitlabTimeFormat)
	tool := glTool{ID: "shipguard", Name: "shipguard", Version: version, Vendor: glVendor{Name: "shipguard"}}
	for _, k := range glKinds {
		status := "success"
		for _, s := range r.Scanners {
			if k.covers(s.Category) && s.Status == "error" {
				status = "failure"
			}
		}
		rep := glReport{
			Version:         gitlabSchemaVersion,
			Scan:            glScan{Analyzer: tool, Scanner: tool, Type: k.scanType, StartTime: ts, EndTime: ts, Status: status},
			Vulnerabilities: []glVuln{},
		}
		for _, f := range r.Findings {
			if !k.covers(f.Category) || (f.Category == finding.CategorySCA && f.Severity < finding.Low && isLicense(f)) {
				continue
			}
			rep.Vulnerabilities = append(rep.Vulnerabilities, glVulnFor(k.scanType, f))
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fmt.Errorf("encode %s: %w", k.file, err)
		}
		if err := os.WriteFile(filepath.Join(dir, k.file), buf.Bytes(), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", k.file, err)
		}
	}
	return nil
}

// isLicense reports whether an SCA finding is a license finding (no
// vulnerability identifier prefix).
func isLicense(f finding.Finding) bool {
	id := strings.ToUpper(f.ID)
	return !strings.HasPrefix(id, "CVE-") && !strings.HasPrefix(id, "GHSA-") && !strings.HasPrefix(id, "OSV-") &&
		!strings.HasPrefix(id, "PYSEC-") && !strings.HasPrefix(id, "GO-") && !strings.HasPrefix(id, "RUSTSEC-")
}

func glVulnFor(scanType string, f finding.Finding) glVuln {
	v := glVuln{
		ID:          f.Fingerprint,
		Name:        f.ID,
		Description: f.Message,
		Severity:    glSeverity(f.Severity),
		Identifiers: []glIdentifier{glIdent(f.ID)},
	}
	for _, a := range f.Aliases {
		v.Identifiers = append(v.Identifiers, glIdent(a))
	}
	v.Location.File = f.File
	switch scanType {
	case "dependency_scanning":
		v.Location.Dependency = &glDependency{Package: glPackage{Name: f.Package}, Version: f.Version}
		if f.FixedVersion != "" {
			v.Solution = "Upgrade to " + f.FixedVersion
		}
	case "secret_detection":
		v.Location.StartLine = f.Line
		v.Location.Commit = &glCommit{SHA: gitlabNoCommit}
	default:
		v.Location.StartLine = f.Line
	}
	return v
}

func glIdent(id string) glIdentifier {
	typ := "shipguard_rule"
	switch u := strings.ToUpper(id); {
	case strings.HasPrefix(u, "CVE-"):
		typ = "cve"
	case strings.HasPrefix(u, "GHSA-"):
		typ = "ghsa"
	}
	return glIdentifier{Type: typ, Name: id, Value: id}
}

func glSeverity(s finding.Severity) string {
	switch s {
	case finding.Critical:
		return "Critical"
	case finding.High:
		return "High"
	case finding.Medium:
		return "Medium"
	case finding.Low:
		return "Low"
	default:
		return "Info"
	}
}
