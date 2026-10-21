package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

// yamlToJSONValue converts YAML to JSON values for the schema, keeping each
// scalar's source text for timestamps so the schema sees what the parser sees.
func yamlToJSONValue(t *testing.T, data []byte) any {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Content) == 0 {
		return nil
	}
	return nodeValue(t, doc.Content[0])
}

func nodeValue(t *testing.T, n *yaml.Node) any {
	t.Helper()
	switch n.Kind {
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = nodeValue(t, n.Content[i+1])
		}
		return m
	case yaml.SequenceNode:
		l := []any{}
		for _, c := range n.Content {
			l = append(l, nodeValue(t, c))
		}
		return l
	}
	if n.Tag == "!!timestamp" {
		return n.Value
	}
	var v any
	if err := n.Decode(&v); err != nil {
		t.Fatal(err)
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
		if len(files) < 5 && wantOK || len(files) < 10 && !wantOK {
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

func TestParseRejectsNullFailOn(t *testing.T) {
	for _, in := range []string{"policy:\n", "policy: {fail_on: null}\n", "policy: {fail_on: {}}\n"} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrConfig) {
			t.Errorf("%q: err = %v, want ErrConfig", in, err)
		}
	}
}

func TestParseExpiresForms(t *testing.T) {
	want := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	for _, v := range []string{"2026-12-31", `"2026-12-31"`} {
		c, err := Parse([]byte("exceptions:\n  - {id: x, reason: r, expires: " + v + "}\n"))
		if err != nil || !c.Exceptions[0].Expires.Equal(want) {
			t.Errorf("%s: %v %v", v, c.Exceptions, err)
		}
	}
	if _, err := Parse([]byte("exceptions:\n  - {id: x, reason: r, expires: 2026-12-31T10:00:00Z}\n")); !errors.Is(err, ErrConfig) {
		t.Errorf("timestamp accepted: %v", err)
	}
}

func TestSASTDefaultExcludes(t *testing.T) {
	if !Defaults().Scanners.SAST.DefaultExcludes {
		t.Error("scanners.sast.default_excludes must default to true")
	}
	c, err := Parse([]byte("scanners:\n  sast: { default_excludes: false }\n"))
	if err != nil || c.Scanners.SAST.DefaultExcludes || !c.Scanners.SAST.Enabled {
		t.Fatalf("false: %+v err=%v", c.Scanners.SAST, err)
	}
	c, err = Parse([]byte("scanners:\n  sast: { enabled: true }\n"))
	if err != nil || !c.Scanners.SAST.DefaultExcludes {
		t.Fatalf("unset: %+v err=%v", c.Scanners.SAST, err)
	}
}

func TestParseRejectsMultipleDocuments(t *testing.T) {
	_, err := Parse([]byte("mode: enforce\n---\nmode: audit\n"))
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "multiple YAML documents are not supported") {
		t.Fatalf("err = %v, want multiple-documents ErrConfig", err)
	}
}

// A later document that is empty (a trailing "---", comments only or null) is
// accepted; one with content is rejected.
func TestParseDocumentMarkers(t *testing.T) {
	for _, in := range []string{
		"---\nmode: audit\n",
		"mode: audit\n---\n",
		"mode: audit\n---\n# comment\n",
		"mode: audit\n---\n~\n",
		"mode: audit\n---\n---\n",
	} {
		c, err := Parse([]byte(in))
		if err != nil || c.Mode != "audit" {
			t.Errorf("Parse(%q) mode = %q, err = %v; want audit", in, c.Mode, err)
		}
	}
	for _, in := range []string{
		"mode: audit\n---\npolicy: {}\n",
		"mode: audit\n---\n- a\n",
		"mode: audit\n---\nfoo\n",
		"mode: audit\n---\n---\npolicy: {}\n",
	} {
		if _, err := Parse([]byte(in)); !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "multiple YAML documents are not supported") {
			t.Errorf("Parse(%q) err = %v; want multiple-documents ErrConfig", in, err)
		}
	}
}

func TestParseRejectsInvalidGlobs(t *testing.T) {
	cases := map[string]string{
		"paths:\n  exclude: [\"web/[a\"]\n":                                                          "paths.exclude[0]",
		"paths:\n  exclude: [\"ok/\", \"{a,b\"]\n":                                                   "paths.exclude[1]",
		"exceptions:\n  - id: CVE-1\n    path: \"src/[x\"\n    reason: r\n    expires: 2030-01-01\n": "exceptions[0]",
	}
	for in, key := range cases {
		_, err := Parse([]byte(in))
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "invalid glob") {
			t.Errorf("Parse(%q) err = %v; want invalid glob naming %s", in, err, key)
		}
	}
}

func TestParseAcceptsValidGlobs(t *testing.T) {
	in := "paths:\n  exclude: [\"vendor/\", \"[x/\", \"**/fixtures/**\", \"*.min.js\"]\n" +
		"exceptions:\n  - id: CVE-1\n    path: \"src/**/*.go\"\n    reason: r\n    expires: 2030-01-01\n"
	if _, err := Parse([]byte(in)); err != nil {
		t.Fatalf("err = %v", err)
	}
}

// validateBoth runs the parser and the schema on one YAML document.
func validateBoth(t *testing.T, schema *jsonschema.Schema, in string) (perr, serr error) {
	t.Helper()
	_, perr = Parse([]byte(in))
	serr = schema.Validate(yamlToJSONValue(t, []byte(in)))
	return perr, serr
}

// per_scanner accepts ms, s, m and h units, with digits before any decimal
// point, in both the parser and the schema.
func TestPerScannerUnitsAgree(t *testing.T) {
	schema := compile(t, "../../schema/shipguard.schema.json")
	for in, wantOK := range map[string]bool{
		"15m": true, "1h": true, "90s": true, "1h30m": true, "1.5h": true, "2h45m30s": true, "0m1s": true,
		"500ms": true, "1m500ms": true, "90000ms": true, "1000us": false, "1000µs": false, "1000000000ns": false, "0ms": false,
		".5s": false, "5.m": false, "+5m": false, "-5m": false, "0s": false, "0.0h": false, "5": false, "m": false,
	} {
		t.Run(in, func(t *testing.T) {
			perr, serr := validateBoth(t, schema, "timeouts:\n  per_scanner: \""+in+"\"\n")
			if (perr == nil) != wantOK {
				t.Errorf("parser: err=%v, want ok=%v", perr, wantOK)
			}
			if perr != nil && !errors.Is(perr, ErrConfig) {
				t.Errorf("parser: err=%v, want ErrConfig", perr)
			}
			if (serr == nil) != wantOK {
				t.Errorf("schema: err=%v, want ok=%v", serr, wantOK)
			}
		})
	}
}

// The schema pattern rejects impossible months and days, but it cannot know
// month lengths or leap years: the parser is authoritative for those, and the
// schema's description says so.
func TestExpiresDatesParserAuthoritative(t *testing.T) {
	schema := compile(t, "../../schema/shipguard.schema.json")
	for _, tc := range []struct {
		date               string
		parserOK, schemaOK bool
	}{
		{"2026-12-31", true, true},
		{"2028-02-29", true, true},
		{"2026-13-01", false, false},
		{"2026-00-10", false, false},
		{"2026-12-32", false, false},
		{"2026-12-00", false, false},
		{"2026-1-01", false, false},
		// Looser schema: valid shape, impossible day.
		{"2026-02-30", false, true},
		{"2027-02-29", false, true},
		{"2026-04-31", false, true},
	} {
		t.Run(tc.date, func(t *testing.T) {
			perr, serr := validateBoth(t, schema, "exceptions:\n  - {id: x, reason: r, expires: \""+tc.date+"\"}\n")
			if (perr == nil) != tc.parserOK {
				t.Errorf("parser: err=%v, want ok=%v", perr, tc.parserOK)
			}
			if (serr == nil) != tc.schemaOK {
				t.Errorf("schema: err=%v, want ok=%v", serr, tc.schemaOK)
			}
		})
	}
	raw, err := os.ReadFile("../../schema/shipguard.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "the parser is authoritative") {
		t.Error("schema expires description must say the parser is authoritative for impossible dates")
	}
}

// An empty file, a comments-only file and a null document all mean "use the
// defaults", in the parser and in the schema.
func TestEmptyConfigIsDefaults(t *testing.T) {
	schema := compile(t, "../../schema/shipguard.schema.json")
	for _, in := range []string{"", "\n", "# only a comment\n", "~\n", "null\n", "---\n"} {
		c, perr := Parse([]byte(in))
		if perr != nil {
			t.Errorf("Parse(%q) err = %v", in, perr)
		} else if !reflect.DeepEqual(c, Defaults()) {
			t.Errorf("Parse(%q) = %+v, want Defaults()", in, c)
		}
		if serr := schema.Validate(yamlToJSONValue(t, []byte(in))); serr != nil {
			t.Errorf("schema(%q) err = %v", in, serr)
		}
	}
}

func TestCIDefaults(t *testing.T) {
	c := Defaults()
	if c.CI.Timeouts.PerStep != 30*time.Minute {
		t.Errorf("per_step = %v, want 30m", c.CI.Timeouts.PerStep)
	}
	for name, s := range map[string]CIStep{"lint": c.CI.Steps.Lint, "test": c.CI.Steps.Test, "build": c.CI.Steps.Build} {
		if !s.On() {
			t.Errorf("step %s is off by default", name)
		}
	}
}

func TestCIValid(t *testing.T) {
	data, err := os.ReadFile("testdata/valid/ci-full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if c.CI.Language != "python" || c.CI.Version != "3.12" || c.CI.Timeouts.PerStep != 45*time.Minute {
		t.Errorf("ci = %+v", c.CI)
	}
	if c.CI.Steps.Lint.Run != "ruff check ." || !c.CI.Steps.Lint.On() {
		t.Errorf("lint = %+v", c.CI.Steps.Lint)
	}
	if got := c.CI.Steps.Test; got.Run != "pytest" || got.Coverage != "reports/coverage.xml" ||
		!reflect.DeepEqual(got.JUnit, []string{"reports/junit.xml", "other/*.xml"}) {
		t.Errorf("test = %+v", got)
	}
	if c.CI.Steps.Build.On() {
		t.Error("build should be disabled")
	}
	for _, lang := range []string{"", "go", "golang", "node", "python", "ruby", "rust"} {
		if _, err := Parse([]byte("ci:\n  language: \"" + lang + "\"\n")); err != nil {
			t.Errorf("language %q: %v", lang, err)
		}
	}
	c, err = Parse([]byte("ci:\n  language: golang\n"))
	if err != nil || c.CI.Language != "golang" {
		t.Errorf("language stored as written: %q, %v", c.CI.Language, err)
	}
}

func TestCIInvalid(t *testing.T) {
	for file, want := range map[string]string{
		"ci-unknown-step.yaml":   "deploy",
		"ci-unknown-key.yaml":    "cmd",
		"ci-bad-language.yaml":   "ci.language",
		"ci-bad-timeout.yaml":    "ci.timeouts.per_step",
		"ci-timeout-zero.yaml":   "ci.timeouts.per_step",
		"ci-timeout-number.yaml": "ci.timeouts.per_step",
		"ci-junit-scalar.yaml":   "junit",
		"ci-run-disabled.yaml":   "run has no effect when enabled is false",
		"ci-version-number.yaml": "ci.version",
		"ci-null.yaml":           "ci",
	} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata/invalid", file))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Parse(data)
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("err = %v, want ErrConfig", err)
			}
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, want it to mention %q", err, want)
			}
		})
	}
}

func TestCISchemaAgrees(t *testing.T) {
	schema := compile(t, "../../schema/shipguard.schema.json")
	for dir, wantOK := range map[string]bool{"testdata/valid": true, "testdata/invalid": false} {
		files, err := filepath.Glob(filepath.Join(dir, "ci-*.yaml"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no ci fixtures (%v)", dir, err)
		}
		for _, f := range files {
			t.Run(f, func(t *testing.T) {
				data, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				perr, serr := validateBoth(t, schema, string(data))
				if (perr == nil) != wantOK || (serr == nil) != wantOK {
					t.Errorf("parser err=%v, schema err=%v, want ok=%v", perr, serr, wantOK)
				}
			})
		}
	}
}

func TestCIPerStepUnitsAgree(t *testing.T) {
	schema := compile(t, "../../schema/shipguard.schema.json")
	for in, wantOK := range map[string]bool{"30m": true, "500ms": true, "1h30m": true, "1000us": false, "0s": false, ".5s": false, "5": false} {
		t.Run(in, func(t *testing.T) {
			perr, serr := validateBoth(t, schema, "ci:\n  timeouts:\n    per_step: \""+in+"\"\n")
			if (perr == nil) != wantOK || (serr == nil) != wantOK {
				t.Errorf("parser err=%v, schema err=%v, want ok=%v", perr, serr, wantOK)
			}
		})
	}
}
