package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/faridlamaul/shipguard/internal/finding"
)

// testdata/sarif-schema-2.1.0.json is the official OASIS SARIF 2.1.0 schema,
// vendored unmodified from
// https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json

func sampleFindings() finding.Result {
	return finding.Result{Findings: []finding.Finding{
		{ID: "CVE-2024-1", Category: finding.CategorySCA, Severity: finding.Critical, File: "go.mod", Line: 0,
			Message: "bad dep", Fingerprint: "fp1", Status: finding.StatusNew},
		{ID: "go.sql", Category: finding.CategorySAST, Severity: finding.High, File: "db/q.go", Line: 12,
			Message: "sql injection", Fingerprint: "fp2", Status: finding.StatusExisting},
		{ID: "iac.rule", Category: finding.CategoryIaC, Severity: finding.Medium, File: "main.tf", Line: 3, Fingerprint: "fp3"},
		{ID: "lic", Category: finding.CategorySCA, Severity: finding.Low, File: "go.sum", Message: "low <&>", Fingerprint: "fp4"},
		{ID: "info.rule", Category: finding.CategorySAST, Severity: finding.Info, Message: "no file", Fingerprint: "fp5"},
		{ID: "go.sql", Category: finding.CategorySAST, Severity: finding.High, File: "db/r.go", Line: 7,
			Message: "other message", Fingerprint: "fp6"},
	}}
}

func renderSARIF(t *testing.T, r finding.Result) (string, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r, "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return buf.String(), doc
}

func compileSARIFSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile("testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var schemaDoc any
	if err := json.Unmarshal(raw, &schemaDoc); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("sarif-schema-2.1.0.json", schemaDoc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func TestSARIFValidatesAgainstSchema(t *testing.T) {
	sch := compileSARIFSchema(t)
	for name, r := range map[string]finding.Result{"findings": sampleFindings(), "empty": {}} {
		_, doc := renderSARIF(t, r)
		if err := sch.Validate(doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if doc["version"] != "2.1.0" || doc["$schema"] != "https://json.schemastore.org/sarif-2.1.0.json" {
			t.Fatalf("%s: bad header %v %v", name, doc["version"], doc["$schema"])
		}
	}
}

func TestSARIFLevelsAndSecuritySeverity(t *testing.T) {
	out, doc := renderSARIF(t, sampleFindings())
	run := doc["runs"].([]any)[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "shipguard" || driver["version"] != "v1.2.3" {
		t.Fatalf("driver %v", driver)
	}
	wantLevel := map[string]string{"CVE-2024-1": "error", "go.sql": "error", "iac.rule": "warning", "lic": "note", "info.rule": "note"}
	wantSev := map[string]string{"CVE-2024-1": "9.5", "go.sql": "8.0", "iac.rule": "5.5", "lic": "3.0", "info.rule": "0.0"}
	for _, x := range run["results"].([]any) {
		m := x.(map[string]any)
		if id := m["ruleId"].(string); m["level"] != wantLevel[id] {
			t.Errorf("%s level %v want %s", id, m["level"], wantLevel[id])
		}
	}
	for _, x := range driver["rules"].([]any) {
		m := x.(map[string]any)
		id := m["id"].(string)
		if got := m["properties"].(map[string]any)["security-severity"]; got != wantSev[id] {
			t.Errorf("%s security-severity %v want %s", id, got, wantSev[id])
		}
	}
	res := run["results"].([]any)
	first := res[0].(map[string]any)
	if first["partialFingerprints"].(map[string]any)["shipguard/v1"] != "fp1" ||
		first["properties"].(map[string]any)["status"] != "new" {
		t.Fatalf("first result %v", first)
	}
	loc := first["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if loc["region"].(map[string]any)["startLine"] != float64(1) ||
		loc["artifactLocation"].(map[string]any)["uri"] != "go.mod" ||
		loc["artifactLocation"].(map[string]any)["uriBaseId"] != "%SRCROOT%" {
		t.Fatalf("location %v", loc)
	}
	if _, ok := res[4].(map[string]any)["locations"]; ok {
		t.Fatal("empty File must have no locations")
	}
	if res[2].(map[string]any)["message"].(map[string]any)["text"] != "iac.rule" {
		t.Fatal("empty message falls back to id")
	}
	if !strings.Contains(out, "low <&>") || !strings.Contains(out, "\n  \"") {
		t.Fatal("expected unescaped HTML and two-space indent")
	}
}

func TestSARIFDedupesRules(t *testing.T) {
	_, doc := renderSARIF(t, sampleFindings())
	run := doc["runs"].([]any)[0].(map[string]any)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	var ids []string
	for _, x := range rules {
		ids = append(ids, x.(map[string]any)["id"].(string))
	}
	if strings.Join(ids, ",") != "CVE-2024-1,go.sql,iac.rule,info.rule,lic" {
		t.Fatalf("rules %v", ids)
	}
	for _, x := range rules {
		m := x.(map[string]any)
		if m["id"] == "go.sql" && m["shortDescription"].(map[string]any)["text"] != "sql injection" {
			t.Fatalf("shortDescription %v", m["shortDescription"])
		}
	}
	results := run["results"].([]any)
	if len(results) != 6 {
		t.Fatalf("results %d", len(results))
	}
	for _, x := range results {
		m := x.(map[string]any)
		if rules[int(m["ruleIndex"].(float64))].(map[string]any)["id"] != m["ruleId"] {
			t.Fatalf("ruleIndex mismatch %v", m)
		}
	}
}

// TestSARIFSkipsInfoLicenses: allowed licenses are info findings and are left
// out, as in the GitLab report; denied licenses and other info findings stay.
func TestSARIFSkipsInfoLicenses(t *testing.T) {
	r := finding.Result{Findings: []finding.Finding{
		{ID: "license:MIT", Category: finding.CategorySCA, Severity: finding.Info, File: "go.mod", Message: "a uses MIT", Fingerprint: "l1"},
		{ID: "license:AGPL-3.0-only", Category: finding.CategorySCA, Severity: finding.High, File: "go.mod", Message: "b uses AGPL", Fingerprint: "l2"},
		{ID: "info.rule", Category: finding.CategorySAST, Severity: finding.Info, File: "a.go", Message: "note", Fingerprint: "s1"},
	}}
	out, _ := renderSARIF(t, r)
	if strings.Contains(out, "license:MIT") {
		t.Errorf("info license in SARIF:\n%s", out)
	}
	for _, want := range []string{"license:AGPL-3.0-only", "info.rule"} {
		if !strings.Contains(out, want) {
			t.Errorf("SARIF missing %s", want)
		}
	}
}

// TestSARIFRulePropertiesAndStatus: a rule's security-severity is the highest
// severity among its results, whatever their order; tags are security plus the
// category; each result carries its diff status ("" when not diffed).
func TestSARIFRulePropertiesAndStatus(t *testing.T) {
	r := finding.Result{Findings: []finding.Finding{
		{ID: "dep", Category: finding.CategorySCA, Severity: finding.Low, File: "go.mod", Fingerprint: "a", Status: finding.StatusExisting},
		{ID: "dep", Category: finding.CategorySCA, Severity: finding.Critical, File: "go.mod", Fingerprint: "b", Status: finding.StatusNew},
		{ID: "dep", Category: finding.CategorySCA, Severity: finding.Medium, File: "go.mod", Fingerprint: "c"},
		{ID: "tf", Category: finding.CategoryIaC, Severity: finding.Medium, File: "main.tf", Fingerprint: "d"},
	}}
	_, doc := renderSARIF(t, r)
	run := doc["runs"].([]any)[0].(map[string]any)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	want := map[string]struct{ sev, tags string }{
		"dep": {"9.5", "security,sca"},
		"tf":  {"5.5", "security,iac"},
	}
	if len(rules) != len(want) {
		t.Fatalf("rules = %v", rules)
	}
	for _, x := range rules {
		m := x.(map[string]any)
		props := m["properties"].(map[string]any)
		var tags []string
		for _, tg := range props["tags"].([]any) {
			tags = append(tags, tg.(string))
		}
		w := want[m["id"].(string)]
		if props["security-severity"] != w.sev || strings.Join(tags, ",") != w.tags {
			t.Errorf("rule %v: properties %v, want security-severity %s tags %s", m["id"], props, w.sev, w.tags)
		}
	}
	var statuses []string
	for _, x := range run["results"].([]any) {
		st := "" // an empty status leaves properties out
		if props, ok := x.(map[string]any)["properties"].(map[string]any); ok {
			st, _ = props["status"].(string)
		}
		statuses = append(statuses, st)
	}
	if got := strings.Join(statuses, ","); got != "existing,new,," {
		t.Errorf("statuses = %q, want %q", got, "existing,new,,")
	}
}

func TestSARIFOmitsEmptyStatus(t *testing.T) {
	var buf bytes.Buffer
	r := finding.Result{Findings: []finding.Finding{{ID: "r1", Category: finding.CategorySAST, Severity: finding.High, File: "a.go", Line: 1, Fingerprint: "fp"}}}
	if err := WriteSARIF(&buf, r, "test"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `"status"`) {
		t.Errorf("empty status emitted: %s", buf.String())
	}
}
