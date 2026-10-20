package report

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/policy"
)

func blocking(n int) []finding.Finding {
	fs := make([]finding.Finding, n)
	for i := range fs {
		fs[i] = finding.Finding{
			ID: fmt.Sprintf("RULE-%d", i), Category: finding.CategorySAST, Severity: finding.High,
			File: fmt.Sprintf("src/file%d.go", i), Line: i + 1, Message: "something is wrong",
		}
	}
	return fs
}

func TestSummaryShowsPolicyChange(t *testing.T) {
	r := finding.Result{PolicyChanged: true, PolicyDiff: "-mode: audit\n+mode: enforce"}
	s := Summary(r, policy.Decision{Result: "pass"}, 0)
	for _, want := range []string{"⚠ Policy changed in this PR", "+mode: enforce"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(Summary(finding.Result{}, policy.Decision{Result: "pass"}, 0), "Policy changed") {
		t.Error("policy warning shown without PolicyChanged")
	}
}

func TestSummarySections(t *testing.T) {
	f := finding.Finding{ID: "A|B", Category: finding.CategorySecrets, Severity: finding.Critical,
		File: "a|b.go", Line: 3, Message: "line1\nline2 | x"}
	r := finding.Result{Findings: []finding.Finding{f}}
	d := policy.Decision{
		Result: "fail", Blocking: []finding.Finding{f}, Total: 1,
		ScannerErrors: []finding.ScannerRun{{Name: "opengrep", Status: "error", Error: "boom"}},
	}
	s := Summary(r, d, 0)
	for _, want := range []string{"FAIL", "opengrep", "boom", `A\|B`, `a\|b.go:3`, "line1 line2 \\| x", "critical", "secrets"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
	rows := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "|") {
			rows++
		}
	}
	if rows != 3 { // header, separator, one row
		t.Errorf("table rows broken by unescaped newline:\n%s", s)
	}
}

func TestSummaryTruncates(t *testing.T) {
	fs := blocking(5000)
	d := policy.Decision{Result: "fail", Blocking: fs, Total: 5000}
	s := Summary(finding.Result{Findings: fs}, d, 10000)
	if len(s) > 10000 {
		t.Fatalf("len = %d, want <= 10000", len(s))
	}
	if !strings.Contains(s, "more findings in .shipguard/findings.json") {
		t.Errorf("missing truncation line")
	}
	if !utf8.ValidString(s) {
		t.Error("invalid UTF-8")
	}
	var more, kept int
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "| ") && strings.Contains(l, "RULE-") {
			kept++
		}
		if _, err := fmt.Sscanf(l, "…and %d more findings in", &more); err == nil {
			continue
		}
	}
	if more == 0 || kept+more != 5000 {
		t.Errorf("kept %d + more %d != 5000", kept, more)
	}
	if full := Summary(finding.Result{Findings: fs}, d, 0); len(full) <= 10000 || strings.Contains(full, "more findings in") {
		t.Errorf("maxBytes 0 must not truncate (len %d)", len(full))
	}
}

func TestSummaryTruncatesTinyLimit(t *testing.T) {
	fs := blocking(10)
	d := policy.Decision{Result: "fail", Blocking: fs, Total: 10}
	for _, n := range []int{1, 7, 50, 120} {
		s := Summary(finding.Result{Findings: fs}, d, n)
		if len(s) > n || !utf8.ValidString(s) {
			t.Errorf("max %d: len %d valid %v", n, len(s), utf8.ValidString(s))
		}
	}
}

func TestSummaryPolicyDiffFence(t *testing.T) {
	r := finding.Result{PolicyChanged: true, PolicyDiff: "+ ```` evil\n" + strings.Repeat("x", 5000)}
	s := Summary(r, policy.Decision{Result: "pass"}, 0)
	if !strings.Contains(s, "`````diff") || !strings.Contains(s, "(diff truncated)") {
		t.Errorf("fence or truncation note missing:\n%.300s", s)
	}
}
