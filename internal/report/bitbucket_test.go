package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/platform"
	"github.com/faridlamaul/shipguard/internal/policy"
)

type recorded struct {
	method, path, auth string
	body               []byte
}

func recorder(t *testing.T, status int) (*httptest.Server, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	var got []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recorded{r.Method, r.URL.Path, r.Header.Get("Authorization"), b})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func manyFindings(n int) finding.Result {
	var r finding.Result
	for i := 0; i < n; i++ {
		sev := finding.Low
		if i == n-1 {
			sev = finding.Critical
		}
		r.Findings = append(r.Findings, finding.Finding{ID: fmt.Sprintf("R%d", i), Category: finding.CategorySAST,
			Severity: sev, File: "a.go", Line: i, Message: "m", Fingerprint: fmt.Sprintf("fp%d", i)})
	}
	return r
}

func TestCodeInsightsBatchesAnnotations(t *testing.T) {
	srv, got := recorder(t, 200)
	r := manyFindings(2500)
	d := policy.Decision{Total: 2500, New: 7}
	ci := CodeInsights{BaseURL: srv.URL, Token: "secret-token", Repo: "ws/repo", Commit: "abc", HTTP: srv.Client()}
	if err := ci.Publish(context.Background(), r, d); err != nil {
		t.Fatal(err)
	}
	var puts, posts, total int
	for i, rec := range *got {
		switch rec.method {
		case http.MethodPut:
			puts++
			if i != 0 || rec.path != "/repositories/ws/repo/commit/abc/reports/shipguard" {
				t.Errorf("put %d path %s", i, rec.path)
			}
		case http.MethodPost:
			posts++
			if rec.path != "/repositories/ws/repo/commit/abc/reports/shipguard/annotations" {
				t.Errorf("post path %s", rec.path)
			}
			var batch []ciAnnotation
			if err := json.Unmarshal(rec.body, &batch); err != nil {
				t.Fatal(err)
			}
			if len(batch) > 100 {
				t.Errorf("batch of %d", len(batch))
			}
			total += len(batch)
		}
		if rec.auth != "Bearer secret-token" {
			t.Errorf("auth = %q", rec.auth)
		}
	}
	if puts != 1 || posts != 10 || total != 1000 {
		t.Fatalf("puts=%d posts=%d total=%d, want 1/10/1000", puts, posts, total)
	}
	var first []ciAnnotation
	_ = json.Unmarshal((*got)[1].body, &first)
	if first[0].Severity != "CRITICAL" || first[0].ExternalID != "fp2499" {
		t.Errorf("first annotation = %+v, want the critical finding first", first[0])
	}
	var rep ciReport
	_ = json.Unmarshal((*got)[0].body, &rep)
	if rep.Result != "PASSED" || rep.Data[0].Value != 7 || rep.Data[1].Value != 2500 || rep.ReportType != "SECURITY" {
		t.Errorf("report = %+v", rep)
	}
}

func TestAnnotationsOrderAndShape(t *testing.T) {
	long := strings.Repeat("é", 600)
	low := finding.Finding{ID: "L", Severity: finding.Info, File: "x", Fingerprint: strings.Repeat("f", 100), Message: long}
	med := finding.Finding{ID: "M", Severity: finding.Medium, File: "y", Line: 3, Fingerprint: "m"}
	blk := finding.Finding{ID: "B", Severity: finding.Low, File: "z", Fingerprint: "b"}
	crit := finding.Finding{ID: "C", Severity: finding.Critical, File: "w", Fingerprint: "c"}
	r := finding.Result{Findings: []finding.Finding{low, med, crit, blk}}
	d := policy.Decision{Blocking: []finding.Finding{blk}}
	a, _ := annotations(r, d)
	var ids []string
	for _, x := range a {
		ids = append(ids, x.Summary[:1])
	}
	if strings.Join(ids, "") != "BCML" {
		t.Fatalf("order = %v", ids)
	}
	if a[3].Severity != "LOW" || len(a[3].ExternalID) != 64 || len(a[3].Summary) > 450 {
		t.Errorf("info annotation = %+v", a[3])
	}
	b, _ := json.Marshal(a[0])
	if strings.Contains(string(b), `"line"`) {
		t.Errorf("line 0 not omitted: %s", b)
	}
}

func TestAnnotationsSkipInfoLicenses(t *testing.T) {
	r := finding.Result{Findings: []finding.Finding{
		{ID: "license:MIT", Category: finding.CategorySCA, Severity: finding.Info, File: "go.mod", Fingerprint: "l1"},
		{ID: "license:AGPL-3.0", Category: finding.CategorySCA, Severity: finding.High, File: "go.mod", Fingerprint: "l2"},
		{ID: "info.rule", Category: finding.CategorySAST, Severity: finding.Info, File: "a.go", Fingerprint: "s1"},
	}}
	var ids []string
	anns, _ := annotations(r, policy.Decision{})
	for _, a := range anns {
		ids = append(ids, a.ExternalID)
	}
	if strings.Join(ids, ",") != "l2,s1" {
		t.Fatalf("annotations = %v, want l2,s1 (no info license)", ids)
	}
}

func reportDetails(t *testing.T, got []recorded) string {
	t.Helper()
	for _, rec := range got {
		if rec.method == http.MethodPut {
			var rep ciReport
			if err := json.Unmarshal(rec.body, &rep); err != nil {
				t.Fatal(err)
			}
			return rep.Details
		}
	}
	t.Fatal("no report PUT")
	return ""
}

// TestCodeInsightsNotesCappedAnnotations: past the 1000-annotation cap the
// report says how many findings are not annotated.
func TestCodeInsightsNotesCappedAnnotations(t *testing.T) {
	srv, got := recorder(t, 200)
	r := manyFindings(2500)
	// Info licenses are never annotated, so they are not counted either.
	r.Findings = append(r.Findings, finding.Finding{ID: "license:MIT", Category: finding.CategorySCA, Severity: finding.Info, Fingerprint: "l"})
	ci := CodeInsights{BaseURL: srv.URL, Repo: "ws/repo", Commit: "abc", HTTP: srv.Client()}
	if err := ci.Publish(context.Background(), r, policy.Decision{Result: "fail", Total: 2501}); err != nil {
		t.Fatal(err)
	}
	details := reportDetails(t, *got)
	if !strings.HasSuffix(details, "…and 1500 more findings in .shipguard/findings.json") || len(details) > maxDetails {
		t.Errorf("details = %q", details)
	}

	srv2, got2 := recorder(t, 200)
	ci.BaseURL, ci.HTTP = srv2.URL, srv2.Client()
	if err := ci.Publish(context.Background(), manyFindings(5), policy.Decision{Result: "pass", Total: 5}); err != nil {
		t.Fatal(err)
	}
	if d := reportDetails(t, *got2); strings.Contains(d, "more findings") {
		t.Errorf("details under the cap = %q", d)
	}
}

func TestCodeInsightsFailedResult(t *testing.T) {
	srv, got := recorder(t, 200)
	ci := CodeInsights{BaseURL: srv.URL, Repo: "ws/repo", Commit: "abc", HTTP: srv.Client()}
	f := finding.Finding{ID: "R", Severity: finding.High, Fingerprint: "x"}
	d := policy.Decision{Result: "fail", Blocking: []finding.Finding{f}}
	if err := ci.Publish(context.Background(), finding.Result{Findings: []finding.Finding{f}}, d); err != nil {
		t.Fatal(err)
	}
	var rep ciReport
	_ = json.Unmarshal((*got)[0].body, &rep)
	if rep.Result != "FAILED" || rep.Details != "shipguard: FAIL" {
		t.Errorf("report = %+v", rep)
	}
}

func TestCodeInsightsUsesProxy(t *testing.T) {
	srv, got := recorder(t, 200)
	ci := CodeInsights{Proxy: srv.URL, Repo: "ws/repo", Commit: "abc"}
	if err := ci.Publish(context.Background(), manyFindings(1), policy.Decision{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 || (*got)[0].method != http.MethodPut {
		t.Fatalf("proxy saw %d requests", len(*got))
	}
}

func TestReportUsesProxyFromEnv(t *testing.T) {
	srv, got := recorder(t, 200)
	env := map[string]string{"BITBUCKET_BUILD_NUMBER": "1", "BITBUCKET_REPO_FULL_NAME": "ws/repo",
		"BITBUCKET_COMMIT": "abc", "SHIPGUARD_BITBUCKET_PROXY": srv.URL}
	err := Report(context.Background(), t.TempDir(), "", finding.Result{}, policy.Decision{}, func(k string) string { return env[k] })
	if err != nil || len(*got) != 1 {
		t.Fatalf("err=%v requests=%d", err, len(*got))
	}
	env["CODE_INSIGHTS"] = "false"
	if err := Report(context.Background(), t.TempDir(), "", finding.Result{}, policy.Decision{}, func(k string) string { return env[k] }); err != nil || len(*got) != 1 {
		t.Fatalf("CODE_INSIGHTS=false still published: err=%v requests=%d", err, len(*got))
	}
}

func TestReportUploadFailureIsWarning(t *testing.T) {
	srv, _ := recorder(t, 403)
	env := map[string]string{"BITBUCKET_BUILD_NUMBER": "1", "BITBUCKET_REPO_FULL_NAME": "ws/repo",
		"BITBUCKET_COMMIT": "abc", "SHIPGUARD_BITBUCKET_PROXY": srv.URL}
	err := Report(context.Background(), t.TempDir(), "bitbucket", finding.Result{}, policy.Decision{}, func(k string) string { return env[k] })
	if !errors.Is(err, ErrUpload) {
		t.Fatalf("err = %v, want ErrUpload", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("err = %v", err)
	}
}

func TestUploadErrorOmitsToken(t *testing.T) {
	ci := CodeInsights{BaseURL: "http://127.0.0.1:1", Token: "super-secret", Repo: "r/r", Commit: "c"}
	err := ci.Publish(context.Background(), finding.Result{}, policy.Decision{})
	if !errors.Is(err, ErrUpload) || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("err = %v", err)
	}
	if err := (CodeInsights{}).Publish(context.Background(), finding.Result{}, policy.Decision{}); !errors.Is(err, ErrUpload) {
		t.Errorf("missing repo: %v", err)
	}
}

func TestReportFormats(t *testing.T) {
	r := finding.Result{ShipguardVersion: "1.2.3", Findings: []finding.Finding{{ID: "R", Severity: finding.High, File: "a", Fingerprint: "x"}}}
	none := func(string) string { return "" }
	dir := t.TempDir()
	if err := Report(context.Background(), dir, "", r, policy.Decision{}, none); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".shipguard", "shipguard.sarif")); err != nil {
		t.Errorf("local auto: %v", err)
	}
	dir = t.TempDir()
	gl := func(k string) string {
		if k == "GITLAB_CI" {
			return "true"
		}
		return ""
	}
	if err := Report(context.Background(), dir, "", r, policy.Decision{}, gl); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".shipguard", "gl-*.json")); len(m) != 3 {
		t.Errorf("gitlab files = %v", m)
	}
	dir = t.TempDir()
	if err := Report(context.Background(), dir, "none", r, policy.Decision{}, none); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".shipguard")); err == nil {
		t.Error("none wrote output")
	}
	if err := Report(context.Background(), dir, "bogus", r, policy.Decision{}, none); err == nil {
		t.Error("unknown format accepted")
	}
}

func TestCodeInsightsProxyDefault(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"step", map[string]string{}, "http://localhost:29418"},
		{"pipe", map[string]string{"BITBUCKET_PIPE_STORAGE_DIR": "/opt/atlassian/pipelines/agent/build/.bitbucket/pipelines/generated/pipeline/pipes/x"}, "http://host.docker.internal:29418"},
		{"override wins in pipe", map[string]string{"BITBUCKET_PIPE_STORAGE_DIR": "/x", "SHIPGUARD_BITBUCKET_PROXY": "http://p:1"}, "http://p:1"},
		{"none", map[string]string{"BITBUCKET_PIPE_STORAGE_DIR": "/x", "SHIPGUARD_BITBUCKET_PROXY": "none"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ci := codeInsightsFromEnv(platform.Context{}, func(k string) string { return tc.env[k] })
			if ci.Proxy != tc.want {
				t.Errorf("Proxy = %q, want %q", ci.Proxy, tc.want)
			}
		})
	}
}
