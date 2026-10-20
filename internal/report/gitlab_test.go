package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// testdata/gitlab/*.json are the official GitLab security report schemas
// (see testdata/gitlab/SOURCE).

var glFiles = map[string]string{
	"gl-secret-detection-report.json":    "secret-detection-report-format.json",
	"gl-sast-report.json":                "sast-report-format.json",
	"gl-dependency-scanning-report.json": "dependency-scanning-report-format.json",
}

var glNow = time.Date(2026, 10, 20, 8, 30, 5, 0, time.UTC)

func glSample() finding.Result {
	return finding.Result{
		Scanners: []finding.ScannerRun{
			{Name: "gitleaks", Category: finding.CategorySecrets, Status: "ok"},
			{Name: "opengrep", Category: finding.CategorySAST, Status: "ok"},
			{Name: "osv", Category: finding.CategorySCA, Status: "error", Error: "boom"},
		},
		Findings: []finding.Finding{
			{ID: "aws-key", Category: finding.CategorySecrets, Severity: finding.High, File: "a.env", Line: 3, Message: "AWS key", Fingerprint: "fs1"},
			{ID: "go.sql", Category: finding.CategorySAST, Severity: finding.High, File: "db/q.go", Line: 12, Message: "sqli", Fingerprint: "fa1"},
			{ID: "iac.rule", Category: finding.CategoryIaC, Severity: finding.Medium, File: "main.tf", Message: "open sg", Fingerprint: "fi1"},
			{ID: "GHSA-xxxx-yyyy-zzzz", Aliases: []string{"CVE-2024-1"}, Category: finding.CategorySCA, Severity: finding.Critical,
				File: "go.mod", Package: "example.com/p", Version: "1.0.0", FixedVersion: "1.0.1", Message: "bad dep", Fingerprint: "fd1"},
			{ID: "GPL-3.0", Category: finding.CategorySCA, Severity: finding.Low, File: "go.sum", Package: "lic", Version: "2", Fingerprint: "fd2"},
			{ID: "MIT", Category: finding.CategorySCA, Severity: finding.Info, File: "go.sum", Package: "m", Version: "1", Fingerprint: "fd3"},
		},
	}
}

func glRead(t *testing.T, dir, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func glSchema(t *testing.T, file string) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "gitlab", file))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(file, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(file)
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func TestGitLabReportsValidate(t *testing.T) {
	for name, r := range map[string]finding.Result{"findings": glSample(), "empty": {}} {
		dir := filepath.Join(t.TempDir(), "out", "gl")
		if err := WriteGitLab(dir, r, "v1.2.3", glNow); err != nil {
			t.Fatal(err)
		}
		for file, schema := range glFiles {
			if err := glSchema(t, schema).Validate(glRead(t, dir, file)); err != nil {
				t.Fatalf("%s/%s: %v", name, file, err)
			}
		}
	}
}

func TestGitLabIaCGoesToSAST(t *testing.T) {
	dir := t.TempDir()
	if err := WriteGitLab(dir, glSample(), "v1.2.3", glNow); err != nil {
		t.Fatal(err)
	}
	sast := glRead(t, dir, "gl-sast-report.json")
	vulns := sast["vulnerabilities"].([]any)
	if len(vulns) != 2 {
		t.Fatalf("sast vulns = %d, want 2", len(vulns))
	}
	v := vulns[1].(map[string]any)
	if v["id"] != "fi1" || v["severity"] != "Medium" || v["name"] != "iac.rule" {
		t.Fatalf("iac vuln %v", v)
	}
	ids := v["identifiers"].([]any)[0].(map[string]any)
	if ids["type"] != "shipguard_rule" || ids["value"] != "iac.rule" {
		t.Fatalf("identifier %v", ids)
	}
	scan := sast["scan"].(map[string]any)
	if scan["type"] != "sast" || scan["status"] != "success" || scan["start_time"] != "2026-10-20T08:30:05" {
		t.Fatalf("scan %v", scan)
	}
	if sast["version"] != gitlabSchemaVersion {
		t.Fatalf("version %v", sast["version"])
	}
}

func TestGitLabDependencyScanning(t *testing.T) {
	dir := t.TempDir()
	if err := WriteGitLab(dir, glSample(), "v1.2.3", glNow); err != nil {
		t.Fatal(err)
	}
	doc := glRead(t, dir, "gl-dependency-scanning-report.json")
	scan := doc["scan"].(map[string]any)
	if scan["status"] != "failure" || scan["type"] != "dependency_scanning" {
		t.Fatalf("scan %v", scan)
	}
	az := scan["analyzer"].(map[string]any)
	if az["id"] != "shipguard" || az["version"] != "v1.2.3" || az["vendor"].(map[string]any)["name"] != "shipguard" {
		t.Fatalf("analyzer %v", az)
	}
	vulns := doc["vulnerabilities"].([]any)
	if len(vulns) != 2 {
		t.Fatalf("vulns = %d, want 2 (info license omitted)", len(vulns))
	}
	v := vulns[0].(map[string]any)
	if v["severity"] != "Critical" || v["solution"] != "Upgrade to 1.0.1" {
		t.Fatalf("vuln %v", v)
	}
	ids := v["identifiers"].([]any)
	if len(ids) != 2 || ids[0].(map[string]any)["type"] != "ghsa" || ids[1].(map[string]any)["type"] != "cve" {
		t.Fatalf("identifiers %v", ids)
	}
	loc := v["location"].(map[string]any)
	dep := loc["dependency"].(map[string]any)
	if loc["file"] != "go.mod" || dep["version"] != "1.0.0" || dep["package"].(map[string]any)["name"] != "example.com/p" {
		t.Fatalf("location %v", loc)
	}
}

func TestGitLabEmptyReportsWritten(t *testing.T) {
	dir := t.TempDir()
	if err := WriteGitLab(dir, finding.Result{}, "v1", glNow); err != nil {
		t.Fatal(err)
	}
	for file := range glFiles {
		doc := glRead(t, dir, file)
		v, ok := doc["vulnerabilities"].([]any)
		if !ok || len(v) != 0 {
			t.Fatalf("%s: vulnerabilities %v", file, doc["vulnerabilities"])
		}
		if doc["scan"].(map[string]any)["status"] != "success" {
			t.Fatalf("%s: status", file)
		}
	}
}

func TestGitLabDeterministic(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	for _, d := range []string{a, b} {
		if err := WriteGitLab(d, glSample(), "v1", glNow); err != nil {
			t.Fatal(err)
		}
	}
	for file := range glFiles {
		x, _ := os.ReadFile(filepath.Join(a, file))
		y, _ := os.ReadFile(filepath.Join(b, file))
		if string(x) != string(y) {
			t.Fatalf("%s differs", file)
		}
	}
}
