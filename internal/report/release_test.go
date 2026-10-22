package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/release"
)

var blocker = finding.Finding{
	ID: "CVE-2026-0001", Scanner: "trivy-image", Category: finding.CategorySCA,
	Severity: finding.Critical, File: "ghcr.io/o/app (linux/amd64) openssl@3.0", Message: "openssl is affected", Fingerprint: "fp",
}

func blockedResult() release.Result {
	return release.Result{
		Released: true, Tag: "v1.4.0", Version: "1.4.0", Image: "ghcr.io/o/app",
		Steps: []release.StepResult{
			{Name: "version", Status: "passed", Reason: "released v1.4.0", Duration: 1500 * time.Millisecond},
			{Name: "binaries", Status: "skipped", Reason: "no .goreleaser.yaml"},
			{Name: "image", Status: "blocked", Reason: "1 image finding(s) above the policy threshold; nothing was pushed", Duration: 2 * time.Second},
		},
		Findings: []finding.Finding{blocker},
		Blocking: []finding.Finding{blocker},
	}
}

func TestWriteReleaseFiles(t *testing.T) {
	dir := t.TempDir()
	if err := WriteRelease(dir, blockedResult()); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, ".shipguard", "release")
	var res struct {
		Released bool   `json:"released"`
		Tag      string `json:"tag"`
		Steps    []struct {
			Name       string `json:"name"`
			Status     string `json:"status"`
			DurationMS int64  `json:"duration_ms"`
		} `json:"steps"`
	}
	b, err := os.ReadFile(filepath.Join(base, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if !res.Released || res.Tag != "v1.4.0" || len(res.Steps) != 3 || res.Steps[0].DurationMS != 1500 || res.Steps[2].Status != "blocked" {
		t.Fatalf("result.json = %s", b)
	}
	sum, _ := os.ReadFile(filepath.Join(base, "summary.md"))
	for _, want := range []string{"| image | blocked |", "CVE-2026-0001", "ghcr.io/o/app", "v1.4.0"} {
		if !strings.Contains(string(sum), want) {
			t.Errorf("summary missing %q:\n%s", want, sum)
		}
	}
	fs, err := finding.ReadResult(filepath.Join(base, "image-findings.json"))
	if err != nil || len(fs.Findings) != 1 || fs.Findings[0].ID != "CVE-2026-0001" {
		t.Fatalf("image-findings.json: %+v %v", fs, err)
	}
}

func TestWriteReleaseNoFindingsWritesEmptyList(t *testing.T) {
	dir := t.TempDir()
	if err := WriteRelease(dir, release.Result{}); err != nil {
		t.Fatal(err)
	}
	fs, err := finding.ReadResult(filepath.Join(dir, ".shipguard", "release", "image-findings.json"))
	if err != nil || fs.Findings == nil || len(fs.Findings) != 0 {
		t.Fatalf("got %+v %v", fs, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".shipguard", "release", "image-findings.json"))
	if !strings.Contains(string(b), `"findings": []`) {
		t.Fatalf("want empty array: %s", b)
	}
}

func TestReleaseOutputsGitHub(t *testing.T) {
	d := t.TempDir()
	out, sum := filepath.Join(d, "out"), filepath.Join(d, "sum")
	r := blockedResult()
	r.ImageDigest = "sha256:abc"
	env := map[string]string{"GITHUB_OUTPUT": out, "GITHUB_STEP_SUMMARY": sum}
	if err := ReleaseOutputs(r, func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	want := "released=true\ntag=v1.4.0\nversion=1.4.0\nimage=ghcr.io/o/app\nimage_digest=sha256:abc\n"
	if string(b) != want {
		t.Fatalf("outputs = %q, want %q", b, want)
	}
	s, _ := os.ReadFile(sum)
	if !strings.Contains(string(s), "CVE-2026-0001") {
		t.Fatalf("summary = %s", s)
	}
}

func TestReleaseOutputsUnset(t *testing.T) {
	if err := ReleaseOutputs(release.Result{}, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseSummaryOnlyBlocking(t *testing.T) {
	r := blockedResult()
	r.Findings = append([]finding.Finding{{ID: "CVE-LOW-1", Severity: finding.Low, File: "x", Message: "m", Category: finding.CategorySCA}}, r.Findings...)
	s := ReleaseSummary(r)
	if !strings.Contains(s, "### Blocking image findings") || !strings.Contains(s, "CVE-2026-0001") || strings.Contains(s, "CVE-LOW-1") {
		t.Fatalf("summary:\n%s", s)
	}
}

func TestReleaseOutputsRejectsNewline(t *testing.T) {
	d := t.TempDir()
	out := filepath.Join(d, "out")
	r := blockedResult()
	r.Image = "ghcr.io/o/app\nreleased=true"
	err := ReleaseOutputs(r, func(k string) string {
		if k == "GITHUB_OUTPUT" {
			return out
		}
		return ""
	})
	if err == nil {
		t.Fatal("want error")
	}
	if _, serr := os.Stat(out); serr == nil {
		t.Fatal("output file must not be written")
	}
}
