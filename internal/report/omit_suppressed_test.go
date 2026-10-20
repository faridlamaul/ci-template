package report

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/policy"
)

func omitSample() finding.Result {
	return finding.Result{Findings: []finding.Finding{
		{ID: "aws-key", Category: finding.CategorySecrets, Severity: finding.High, File: "a.env", Line: 3, Message: "m", Fingerprint: "SUP-S"},
		{ID: "go.sql", Category: finding.CategorySAST, Severity: finding.High, File: "db/q.go", Line: 12, Message: "m", Fingerprint: "SUP-A"},
		{ID: "GHSA-x", Category: finding.CategorySCA, Severity: finding.Critical, File: "go.mod", Package: "p", Version: "1", Message: "m", Fingerprint: "SUP-D"},
		{ID: "expired.rule", Category: finding.CategorySAST, Severity: finding.High, File: "e.go", Line: 1, Message: "m", Fingerprint: "KEEP-EXPIRED"},
		{ID: "old.rule", Category: finding.CategorySAST, Severity: finding.High, File: "o.go", Line: 1, Message: "m", Fingerprint: "KEEP-EXISTING", Status: finding.StatusExisting},
		{ID: "low.rule", Category: finding.CategorySAST, Severity: finding.Low, File: "l.go", Line: 1, Message: "m", Fingerprint: "KEEP-LOW"},
		{ID: "nofp", Category: finding.CategorySAST, Severity: finding.High, File: "n.go", Line: 1, Message: "m", Fingerprint: "nofp"},
	}}
}

func omitDecision(r finding.Result) policy.Decision {
	return policy.Decision{
		Result:     "fail",
		Blocking:   []finding.Finding{r.Findings[3]},
		Suppressed: []finding.Finding{r.Findings[0], r.Findings[1], r.Findings[2]},
		Expired:    []policy.Exception{{ID: "expired.rule", Expires: time.Now()}},
		Total:      len(r.Findings),
	}
}

func assertOmitted(t *testing.T, what, out string) {
	t.Helper()
	for _, fp := range []string{"SUP-S", "SUP-A", "SUP-D"} {
		if strings.Contains(out, fp) {
			t.Errorf("%s contains suppressed %s", what, fp)
		}
	}
	for _, fp := range []string{"KEEP-EXPIRED", "KEEP-EXISTING", "KEEP-LOW"} {
		if !strings.Contains(out, fp) {
			t.Errorf("%s lost %s", what, fp)
		}
	}
	if !strings.Contains(out, "nofp") {
		t.Errorf("%s lost the finding without a fingerprint", what)
	}
}

func TestReportable(t *testing.T) {
	r := omitSample()
	got := reportable(r.Findings, omitDecision(r))
	if len(got) != 4 {
		t.Fatalf("got %d findings, want 4: %+v", len(got), got)
	}
	// A suppressed finding with an empty fingerprint must not drop others.
	a := finding.Finding{ID: "a", File: "a.go", Line: 1}
	b := finding.Finding{ID: "b", File: "b.go", Line: 1}
	got = reportable([]finding.Finding{a, b}, policy.Decision{Suppressed: []finding.Finding{a}})
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("got %+v", got)
	}
}

func TestReportOmitsSuppressedSARIF(t *testing.T) {
	r := omitSample()
	dir := t.TempDir()
	if err := Report(context.Background(), dir, "sarif", r, omitDecision(r), func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, SARIFFile))
	if err != nil {
		t.Fatal(err)
	}
	assertOmitted(t, "sarif", string(b))
	if strings.Contains(string(b), "suppressions") {
		t.Error("sarif must not carry suppressions")
	}
}

func TestReportOmitsSuppressedGitLab(t *testing.T) {
	r := omitSample()
	r.ShipguardVersion = "v1"
	dir := t.TempDir()
	if err := Report(context.Background(), dir, "gitlab", r, omitDecision(r), func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for file, schema := range glFiles {
		b, err := os.ReadFile(filepath.Join(dir, outDir, file))
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
		if err := glSchema(t, schema).Validate(glRead(t, filepath.Join(dir, outDir), file)); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	assertOmitted(t, "gitlab", all.String())
}

func TestPublishOmitsSuppressed(t *testing.T) {
	srv, got := recorder(t, 200)
	r := omitSample()
	d := omitDecision(r)
	ci := CodeInsights{BaseURL: srv.URL, Token: "t", Repo: "ws/repo", Commit: "abc", HTTP: srv.Client()}
	if err := ci.Publish(context.Background(), r, d); err != nil {
		t.Fatal(err)
	}
	var posted, put strings.Builder
	for _, rec := range *got {
		if rec.method == "POST" {
			posted.Write(rec.body)
		} else {
			put.Write(rec.body)
		}
	}
	assertOmitted(t, "bitbucket annotations", posted.String())
	// The result still comes from the full decision (blocking finding present).
	if !strings.Contains(put.String(), `"FAILED"`) {
		t.Errorf("report result: %s", put.String())
	}
}
