package scanner_test

import (
	"os"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/policy"
	"github.com/faridlamaul/shipguard/internal/scanner"
)

func TestParseTrivyImage(t *testing.T) {
	raw, err := os.ReadFile("testdata/trivy-image.json")
	if err != nil {
		t.Fatal(err)
	}
	fs, err := scanner.ParseTrivyImage(raw, "ghcr.io/o/app:1.2.3", "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3", len(fs))
	}
	for _, f := range fs {
		if f.Category != finding.CategorySCA || f.Scanner != "trivy-image" || f.Fingerprint == "" {
			t.Fatalf("bad finding %+v", f)
		}
	}
	a, b, c := fs[0], fs[1], fs[2]
	if a.ID != "CVE-2023-42363" || a.Severity != finding.Medium || !a.FixAvailable ||
		a.FixedVersion != "1.36.1-r7" || a.Package != "busybox" || a.Version != "1.36.1-r2" ||
		a.File != "ghcr.io/o/app:1.2.3 (linux/amd64) busybox@1.36.1-r2" {
		t.Fatalf("a = %+v", a)
	}
	if b.ID != "CVE-2022-40897" || b.Severity != finding.High || !b.FixAvailable {
		t.Fatalf("b = %+v", b)
	}
	if c.ID != "CVE-2023-5752" || c.Severity != finding.Medium || c.FixAvailable || c.FixedVersion != "" {
		t.Fatalf("c = %+v (UNKNOWN severity maps to medium, no fix)", c)
	}
	again, _ := scanner.ParseTrivyImage(raw, "ghcr.io/o/app:1.2.3", "linux/amd64")
	for i := range fs {
		if fs[i].Fingerprint != again[i].Fingerprint {
			t.Fatalf("fingerprint %d not stable", i)
		}
	}
}

func TestParseTrivyImageEmpty(t *testing.T) {
	fs, err := scanner.ParseTrivyImage([]byte(`{"Results":null}`), "i", "p")
	if err != nil || len(fs) != 0 {
		t.Fatalf("got %v, %v", fs, err)
	}
}

func TestParseTrivyImageInvalid(t *testing.T) {
	if _, err := scanner.ParseTrivyImage([]byte("not json"), "i", "p"); err == nil {
		t.Fatal("want error")
	}
}

func TestTrivyImageFixOnlyNotBlocking(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"t","Vulnerabilities":[
		{"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1","Severity":"CRITICAL"}]}]}`)
	fs, err := scanner.ParseTrivyImage(raw, "img", "linux/amd64")
	if err != nil || len(fs) != 1 {
		t.Fatalf("got %v, %v", fs, err)
	}
	cfg := policy.Defaults()
	cfg.Policy.FailOn[finding.CategorySCA] = policy.Threshold{Severity: finding.High, FixAvailableOnly: true}
	r := finding.Result{Findings: fs, Scanners: []finding.ScannerRun{{Name: "trivy-image", Status: "ok"}}}
	if got := policy.Evaluate(r, cfg, false, time.Now()).ExitCode(); got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
}
