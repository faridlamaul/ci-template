package finding

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSeverityRoundTrip(t *testing.T) {
	names := map[Severity]string{Critical: "critical", High: "high", Medium: "medium", Low: "low", Info: "info"}
	for sev, name := range names {
		b, err := sev.MarshalText()
		if err != nil || string(b) != name {
			t.Fatalf("MarshalText(%d) = %q, %v; want %q", sev, b, err, name)
		}
		var got Severity
		if err := got.UnmarshalText([]byte(name)); err != nil || got != sev {
			t.Fatalf("UnmarshalText(%q) = %d, %v; want %d", name, got, err, sev)
		}
		p, err := ParseSeverity(name)
		if err != nil || p != sev {
			t.Fatalf("ParseSeverity(%q) = %d, %v", name, p, err)
		}
	}
	if _, err := ParseSeverity("ERROR"); err == nil {
		t.Fatal("ParseSeverity(ERROR) should fail")
	}
}

func TestFingerprintIgnoresLineAndWhitespace(t *testing.T) {
	a := Fingerprint("r1", "a.go", "if x {\n\t\tfoo()\n}")
	b := Fingerprint("r1", "a.go", "  if x {   foo() }  ")
	if a != b {
		t.Fatalf("whitespace changed fingerprint: %s vs %s", a, b)
	}
	if a == Fingerprint("r1", "b.go", "if x { foo() }") {
		t.Fatal("different file must differ")
	}
	if NormalizeSnippet(" a \t\n b ") != "a b" {
		t.Fatal("NormalizeSnippet wrong")
	}
	if SecretKey("s3cret") == "s3cret" || len(SecretKey("s3cret")) != 64 {
		t.Fatal("SecretKey must be a sha256 hex")
	}
}

func TestFilterPaths(t *testing.T) {
	fs := []Finding{{File: "vendor/a/b.go"}, {File: "x/testdata/y"}, {File: "main.go"}}
	got := FilterPaths(fs, []string{"vendor/", "**/testdata/**"})
	if len(got) != 1 || got[0].File != "main.go" {
		t.Fatalf("got %+v", got)
	}
	if len(FilterPaths(fs, nil)) != 3 {
		t.Fatal("no patterns keeps all")
	}
}

func TestResultRoundTrip(t *testing.T) {
	r := Result{
		SchemaVersion:    1,
		ShipguardVersion: "v0.1.0",
		Scanners:         []ScannerRun{{Name: "gitleaks", Category: "secrets", Status: "ok", DurationMS: 12}},
		Findings: []Finding{{ID: "CVE-1", Scanner: "osv", Category: "sca", Severity: High, File: "go.mod",
			Package: "p", Version: "1", Fingerprint: "fp", Status: "new"}},
		PolicyChanged: true,
		PolicyDiff:    "diff",
	}
	path := filepath.Join(t.TempDir(), "findings.json")
	if err := WriteResult(path, r); err != nil {
		t.Fatal(err)
	}
	got, err := ReadResult(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, r) {
		t.Fatalf("got %+v want %+v", got, r)
	}
}

func TestLicenseKey(t *testing.T) {
	cases := map[string]string{
		"GPL-3.0": "gpl-3.0", "GPL-3.0-only": "gpl-3.0", "GPL-3.0-or-later": "gpl-3.0", "GPL-3.0+": "gpl-3.0",
		" AGPL-3.0-ONLY ": "agpl-3.0", "MIT": "mit", "Apache-2.0": "apache-2.0", "": "",
	}
	for in, want := range cases {
		if got := LicenseKey(in); got != want {
			t.Errorf("LicenseKey(%q) = %q want %q", in, got, want)
		}
	}
}

func TestRunStatusesMatchSchema(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "schema", "findings.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{RunStatusOK, RunStatusError, RunStatusSkipped} {
		if !strings.Contains(string(b), `"`+s+`"`) {
			t.Errorf("run status %q is not in the findings schema", s)
		}
	}
	if RunStatusOK != "ok" || RunStatusError != "error" || RunStatusSkipped != "skipped" {
		t.Fatalf("run status values changed: %q %q %q", RunStatusOK, RunStatusError, RunStatusSkipped)
	}
}

func TestResultNilSlicesMarshalEmpty(t *testing.T) {
	b, err := json.Marshal(Result{SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"scanners":[]`, `"findings":[]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("json = %s, want it to contain %s", b, want)
		}
	}
	path := filepath.Join(t.TempDir(), "findings.json")
	if err := WriteResult(path, Result{SchemaVersion: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"scanners": []`, `"findings": []`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("findings.json = %s, want it to contain %s", got, want)
		}
	}
}

func TestWriteResultCreatesParentAndReplacesAtomically(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	path := filepath.Join(dir, "findings.json")
	if err := WriteResult(path, Result{SchemaVersion: 1, ShipguardVersion: "old"}); err != nil {
		t.Fatalf("WriteResult into a missing dir: %v", err)
	}
	if err := WriteResult(path, Result{SchemaVersion: 1, ShipguardVersion: "new"}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadResult(path)
	if err != nil || got.ShipguardVersion != "new" {
		t.Fatalf("got %+v, %v; want version new", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir holds %v; want only findings.json (no temp files left)", names)
	}
	// A failed encode leaves the previous file untouched.
	bad := Result{Findings: []Finding{{Severity: Severity(99)}}}
	if err := WriteResult(path, bad); err == nil {
		t.Fatal("want an encode error for an invalid severity")
	}
	if got, err := ReadResult(path); err != nil || got.ShipguardVersion != "new" {
		t.Fatalf("after a failed write: %+v, %v", got, err)
	}
}

func TestReadResultMissingSeverityIsError(t *testing.T) {
	for name, f := range map[string]string{
		"absent": `{"id":"x","scanner":"s","category":"sast","file":"a","message":"m","fingerprint":"fp"}`,
		"null":   `{"id":"x","severity":null,"scanner":"s","category":"sast","file":"a","message":"m","fingerprint":"fp"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "findings.json")
			doc := `{"schema_version":1,"scanners":[],"findings":[` + f + `]}`
			if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadResult(path); err == nil || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("err = %v, want a missing-severity error", err)
			}
		})
	}
	var f Finding
	if err := json.Unmarshal([]byte(`{"id":"x","severity":"info"}`), &f); err != nil || f.Severity != Info || f.ID != "x" {
		t.Fatalf("explicit info: %+v, %v", f, err)
	}
}

func TestFilterPathsSkipsMalformedGlob(t *testing.T) {
	fs := []Finding{{File: "vendor/a.go"}, {File: "main.go"}, {File: "[x"}}
	got := FilterPaths(fs, []string{"[", "vendor/**"})
	if len(got) != 2 || got[0].File != "main.go" || got[1].File != "[x" {
		t.Fatalf("got %+v; want the malformed pattern skipped and the others applied", got)
	}
}

func TestIsLicenseNeedsSCACategory(t *testing.T) {
	cases := []struct {
		f    Finding
		want bool
	}{
		{Finding{ID: LicensePrefix + "GPL-3.0", Category: CategorySCA}, true},
		{Finding{ID: LicensePrefix + "GPL-3.0", Category: CategorySAST}, false},
		{Finding{ID: LicensePrefix + "GPL-3.0", Category: CategoryIaC}, false},
		{Finding{ID: "GHSA-xxxx", Category: CategorySCA}, false},
	}
	for _, c := range cases {
		if got := IsLicense(c.f); got != c.want {
			t.Errorf("IsLicense(%s/%s) = %v, want %v", c.f.Category, c.f.ID, got, c.want)
		}
	}
}
