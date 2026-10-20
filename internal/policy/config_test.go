package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/faridlamaul/shipguard/internal/finding"
)

func TestDefaultsMatchSpec(t *testing.T) {
	c := Defaults()
	if c.Version != 1 || c.Mode != "enforce" {
		t.Errorf("version/mode = %d/%q", c.Version, c.Mode)
	}
	if len(c.Paths.Exclude) != 0 {
		t.Errorf("paths.exclude = %v, want empty", c.Paths.Exclude)
	}
	if !c.Scanners.Secrets.Enabled || !c.Scanners.SAST.Enabled || !c.Scanners.SCA.Enabled || !c.Scanners.IaC.Enabled {
		t.Errorf("all scanners must default to enabled: %+v", c.Scanners)
	}
	if c.Timeouts.PerScanner != 15*time.Minute {
		t.Errorf("per_scanner = %v", c.Timeouts.PerScanner)
	}
	want := map[finding.Category]Threshold{
		finding.CategorySecrets: {Any: true},
		finding.CategorySAST:    {Severity: finding.High},
		finding.CategorySCA:     {Severity: finding.High, FixAvailableOnly: true},
		finding.CategoryIaC:     {Severity: finding.High},
	}
	if len(c.Policy.FailOn) != len(want) {
		t.Fatalf("fail_on = %v", c.Policy.FailOn)
	}
	for k, w := range want {
		if got := c.Policy.FailOn[k]; got != w {
			t.Errorf("fail_on[%s] = %+v, want %+v", k, got, w)
		}
	}
	if len(c.Exceptions) != 0 {
		t.Errorf("exceptions = %v", c.Exceptions)
	}
}

func TestParseRejectsUnknownKey(t *testing.T) {
	_, err := Parse([]byte("policy: {fail_ON: {}}\n"))
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestParseRejectsExceptionWithoutExpires(t *testing.T) {
	_, err := Parse([]byte("exceptions:\n  - id: CVE-1\n    reason: because\n"))
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "expires") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseThresholdForms(t *testing.T) {
	c, err := Parse([]byte(`
policy:
  fail_on:
    secrets: any
    sast: critical
    sca: { severity: critical, fix_available_only: false }
`))
	if err != nil {
		t.Fatal(err)
	}
	f := c.Policy.FailOn
	if !f[finding.CategorySecrets].Any {
		t.Errorf("secrets = %+v", f[finding.CategorySecrets])
	}
	if f[finding.CategorySAST] != (Threshold{Severity: finding.Critical}) {
		t.Errorf("sast = %+v", f[finding.CategorySAST])
	}
	if f[finding.CategorySCA] != (Threshold{Severity: finding.Critical}) {
		t.Errorf("sca = %+v (must replace default entirely)", f[finding.CategorySCA])
	}
	if f[finding.CategoryIaC] != (Threshold{Severity: finding.High}) {
		t.Errorf("iac default lost: %+v", f[finding.CategoryIaC])
	}
}

func TestParseMergesOverDefaults(t *testing.T) {
	c, err := Parse([]byte("mode: audit\nscanners:\n  iac: { enabled: false }\nexceptions:\n  - {id: x, reason: r, expires: 2026-12-31}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "audit" || c.Scanners.IaC.Enabled || !c.Scanners.SAST.Enabled || c.Timeouts.PerScanner != 15*time.Minute {
		t.Errorf("merge wrong: %+v", c)
	}
	if got := c.Exceptions[0].Expires; !got.Equal(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("expires = %v", got)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "enforce" || c.Version != 1 {
		t.Errorf("c = %+v", c)
	}
}

func TestLoadInvalidFileWrapsErrConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".shipguard.yaml")
	if err := os.WriteFile(p, []byte("mode: nope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); !errors.Is(err, ErrConfig) {
		t.Fatalf("err = %v", err)
	}
}

// yamlToJSONValue converts YAML into values the JSON Schema validator accepts.
func yamlToJSONValue(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(normalize(v)) // time.Time becomes a date string
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = normalize(e)
		}
	case []any:
		for i, e := range x {
			x[i] = normalize(e)
		}
	case time.Time:
		return x.Format("2006-01-02")
	}
	return v
}

func compile(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	s, err := jsonschema.NewCompiler().Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSchemaAgreesWithParser(t *testing.T) {
	schema := compile(t, "../../schema/shipguard.schema.json")
	for dir, wantOK := range map[string]bool{"testdata/valid": true, "testdata/invalid": false} {
		files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) < 4 && wantOK || len(files) < 6 && !wantOK {
			t.Fatalf("%s has only %d files", dir, len(files))
		}
		for _, f := range files {
			t.Run(f, func(t *testing.T) {
				data, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				_, perr := Parse(data)
				serr := schema.Validate(yamlToJSONValue(t, data))
				if (perr == nil) != wantOK {
					t.Errorf("parser: err=%v, want ok=%v", perr, wantOK)
				}
				if (serr == nil) != wantOK {
					t.Errorf("schema: err=%v, want ok=%v", serr, wantOK)
				}
			})
		}
	}
}

func TestFindingsSchemaAcceptsResult(t *testing.T) {
	schema := compile(t, "../../schema/findings.schema.json")
	r := finding.Result{
		SchemaVersion: 1, ShipguardVersion: "dev",
		Scanners: []finding.ScannerRun{{Name: "gitleaks", Category: finding.CategorySecrets, Status: "ok", DurationMS: 5}},
		Findings: []finding.Finding{{ID: "r1", Scanner: "gitleaks", Category: finding.CategorySecrets, Severity: finding.High,
			File: "a.go", Line: 3, Message: "m", Fingerprint: "abc", Status: finding.StatusNew}},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(v); err != nil {
		t.Fatal(err)
	}
	v.(map[string]any)["extra"] = 1
	if schema.Validate(v) == nil {
		t.Error("unknown top-level key must be rejected")
	}
}
