package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
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
			{ID: "license:GPL-3.0", Category: finding.CategorySCA, Severity: finding.Low, File: "go.sum", Package: "lic", Version: "2", Fingerprint: "fd2"},
			{ID: "license:MIT", Category: finding.CategorySCA, Severity: finding.Info, File: "go.sum", Package: "m", Version: "1", Fingerprint: "fd3"},
			{ID: "MAL-2024-1", Category: finding.CategorySCA, Severity: finding.Info, File: "go.sum", Package: "mal", Version: "1", Fingerprint: "fd4"},
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

var (
	glSchemaMu    sync.Mutex
	glSchemaCache = map[string]*jsonschema.Schema{}
)

// glSchema compiles a vendored schema once per test binary.
func glSchema(t *testing.T, file string) *jsonschema.Schema {
	t.Helper()
	glSchemaMu.Lock()
	defer glSchemaMu.Unlock()
	if sch, ok := glSchemaCache[file]; ok {
		return sch
	}
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
	glSchemaCache[file] = sch
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
	if len(vulns) != 3 {
		t.Fatalf("vulns = %d, want 3 (info license omitted, info MAL kept)", len(vulns))
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

func TestGitLabSecretCommitSHA(t *testing.T) {
	secret := func(r finding.Result) any {
		dir := t.TempDir()
		if err := WriteGitLab(dir, r, "v1", glNow); err != nil {
			t.Fatal(err)
		}
		doc := glRead(t, dir, "gl-secret-detection-report.json")
		loc := doc["vulnerabilities"].([]any)[0].(map[string]any)["location"].(map[string]any)
		return loc["commit"].(map[string]any)["sha"]
	}
	r := glSample()
	if got := secret(r); got != gitlabNoCommit {
		t.Fatalf("no context: sha = %v", got)
	}
	r.Context = json.RawMessage(`{"platform":"gitlab","head_sha":"abc123"}`)
	if got := secret(r); got != "abc123" {
		t.Fatalf("with context: sha = %v", got)
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

// TestGitLabLicenseIdentifierType: the schema leaves identifier types
// analyzer-dependent; a denied license is identified as a license, not as a
// shipguard rule.
func TestGitLabLicenseIdentifierType(t *testing.T) {
	dir := t.TempDir()
	if err := WriteGitLab(dir, glSample(), "v1", glNow); err != nil {
		t.Fatal(err)
	}
	doc := glRead(t, dir, "gl-dependency-scanning-report.json")
	types := map[string]string{}
	for _, v := range doc["vulnerabilities"].([]any) {
		id := v.(map[string]any)["identifiers"].([]any)[0].(map[string]any)
		types[id["value"].(string)] = id["type"].(string)
	}
	if types["license:GPL-3.0"] != "license" || types["MAL-2024-1"] != "shipguard_rule" || types["GHSA-xxxx-yyyy-zzzz"] != "ghsa" {
		t.Fatalf("identifier types = %v", types)
	}
	if err := glSchema(t, glFiles["gl-dependency-scanning-report.json"]).Validate(doc); err != nil {
		t.Fatal(err)
	}
}

// TestGitLabSchemaCompiledOnce: each vendored schema is compiled once per test
// binary and reused.
func TestGitLabSchemaCompiledOnce(t *testing.T) {
	file := glFiles["gl-sast-report.json"]
	if a, b := glSchema(t, file), glSchema(t, file); a != b {
		t.Fatal("schema compiled twice")
	}
}
