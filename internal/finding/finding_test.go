package finding

import (
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
