package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/faridlamaul/shipguard/internal/policy"
)

func TestWriteOutputsGitHubAndDotenv(t *testing.T) {
	dir := t.TempDir()
	gh := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(gh, []byte("existing=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := policy.Decision{Result: "fail", New: 2, Total: 7}
	env := func(k string) string {
		if k == "GITHUB_OUTPUT" {
			return gh
		}
		return ""
	}
	if err := WriteOutputs(dir, d, env); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".shipguard", "gate.env"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "SHIPGUARD_RESULT=fail\nSHIPGUARD_NEW_FINDINGS=2\nSHIPGUARD_TOTAL_FINDINGS=7\n"; string(b) != want {
		t.Errorf("gate.env = %q, want %q", b, want)
	}
	b, _ = os.ReadFile(gh)
	if want := "existing=1\nresult=fail\nnew_findings=2\ntotal_findings=7\n"; string(b) != want {
		t.Errorf("GITHUB_OUTPUT = %q, want %q", b, want)
	}
}

func TestWriteOutputsWithoutGitHubOutput(t *testing.T) {
	dir := t.TempDir()
	if err := WriteOutputs(dir, policy.Decision{Result: "pass"}, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".shipguard", "gate.env")); err != nil {
		t.Fatal(err)
	}
}
