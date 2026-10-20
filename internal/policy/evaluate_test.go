package policy

import (
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
)

var evalNow = time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)

func fnd(id string, cat finding.Category, sev finding.Severity, fix bool) finding.Finding {
	return finding.Finding{ID: id, Category: cat, Severity: sev, FixAvailable: fix, File: "a.go", Fingerprint: "fp-" + id, Status: finding.StatusNew}
}

func res(fs ...finding.Finding) finding.Result {
	return finding.Result{Findings: fs, Scanners: []finding.ScannerRun{{Name: "x", Status: "ok"}}}
}

func TestEvaluateDefaultThresholds(t *testing.T) {
	tests := []struct {
		name string
		f    finding.Finding
		want bool
	}{
		{"secret info", fnd("s", finding.CategorySecrets, finding.Info, false), true},
		{"secret low", fnd("s", finding.CategorySecrets, finding.Low, false), true},
		{"sast medium", fnd("a", finding.CategorySAST, finding.Medium, false), false},
		{"sast high", fnd("a", finding.CategorySAST, finding.High, false), true},
		{"sca high no fix", fnd("c", finding.CategorySCA, finding.High, false), false},
		{"sca high fix", fnd("c", finding.CategorySCA, finding.High, true), true},
		{"iac critical", fnd("i", finding.CategoryIaC, finding.Critical, false), true},
		{"iac medium", fnd("i", finding.CategoryIaC, finding.Medium, false), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Evaluate(res(tc.f), Defaults(), false, evalNow)
			if got := len(d.Blocking) == 1; got != tc.want {
				t.Fatalf("blocking = %v, want %v", got, tc.want)
			}
			wantExit, wantRes := 0, "pass"
			if tc.want {
				wantExit, wantRes = 1, "fail"
			}
			if d.ExitCode() != wantExit || d.Result != wantRes {
				t.Fatalf("exit=%d result=%s", d.ExitCode(), d.Result)
			}
			if d.Total != 1 || d.New != 1 {
				t.Fatalf("counts %d/%d", d.New, d.Total)
			}
		})
	}
}

func TestEvaluateNoThresholdNeverBlocks(t *testing.T) {
	cfg := Defaults()
	delete(cfg.Policy.FailOn, finding.CategoryIaC)
	d := Evaluate(res(fnd("i", finding.CategoryIaC, finding.Critical, true)), cfg, false, evalNow)
	if len(d.Blocking) != 0 {
		t.Fatal("category without threshold must not block")
	}
}

func TestEvaluatePRBlocksOnlyNew(t *testing.T) {
	f := fnd("a", finding.CategorySAST, finding.High, false)
	f.Status = finding.StatusExisting
	if d := Evaluate(res(f), Defaults(), true, evalNow); len(d.Blocking) != 0 || d.New != 0 || d.Total != 1 {
		t.Fatalf("PR: %+v", d)
	}
	if d := Evaluate(res(f), Defaults(), false, evalNow); len(d.Blocking) != 1 {
		t.Fatalf("push: %+v", d)
	}
}

func cfgWithException(e Exception) Config {
	c := Defaults()
	c.Exceptions = []Exception{e}
	return c
}

func TestExceptionSuppressesByAlias(t *testing.T) {
	f := fnd("GHSA-xxxx", finding.CategorySCA, finding.High, true)
	f.Aliases = []string{"CVE-2026-1"}
	cfg := cfgWithException(Exception{ID: "CVE-2026-1", Reason: "r", Expires: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)})
	d := Evaluate(res(f), cfg, false, evalNow)
	if len(d.Blocking) != 0 || len(d.Suppressed) != 1 || d.ExitCode() != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestExceptionMatchesFingerprintAndPath(t *testing.T) {
	f := fnd("a", finding.CategorySAST, finding.High, false)
	f.File = "src/deep/x.go"
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		e    Exception
		want bool
	}{
		{Exception{ID: "fp-a", Expires: exp}, true},
		{Exception{ID: "a", Path: "src/deep/x.go", Expires: exp}, true},
		{Exception{ID: "a", Path: "src/**/*.go", Expires: exp}, true},
		{Exception{ID: "a", Path: "other/**", Expires: exp}, false},
		{Exception{ID: "b", Expires: exp}, false},
	} {
		d := Evaluate(res(f), cfgWithException(tc.e), false, evalNow)
		if (len(d.Suppressed) == 1) != tc.want {
			t.Fatalf("%+v: suppressed=%d", tc.e, len(d.Suppressed))
		}
	}
}

func TestExceptionExpiryBoundary(t *testing.T) {
	f := fnd("a", finding.CategorySAST, finding.High, false)
	e := Exception{ID: "a", Reason: "r", Expires: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)}
	cfg := cfgWithException(e)

	d := Evaluate(res(f), cfg, false, time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC))
	if len(d.Suppressed) != 1 || len(d.Blocking) != 0 || len(d.Expired) != 0 {
		t.Fatalf("still active: %+v", d)
	}
	d = Evaluate(res(f), cfg, false, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(d.Suppressed) != 0 || len(d.Blocking) != 1 || len(d.Expired) != 1 || d.Expired[0].ID != "a" {
		t.Fatalf("expired: %+v", d)
	}
	// Exception matching nothing is not listed; duplicates are collapsed.
	g := fnd("a", finding.CategorySAST, finding.High, false)
	g.Fingerprint = "other"
	d = Evaluate(res(f, g), cfg, false, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(d.Expired) != 1 {
		t.Fatalf("expired not deduplicated: %+v", d.Expired)
	}
	d = Evaluate(res(), cfg, false, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(d.Expired) != 0 {
		t.Fatal("unmatched exception listed")
	}
}

func TestAuditModeExitZero(t *testing.T) {
	cfg := Defaults()
	cfg.Mode = "audit"
	d := Evaluate(res(fnd("s", finding.CategorySecrets, finding.High, false)), cfg, false, evalNow)
	if d.Result != "audit" || len(d.Blocking) != 1 || d.ExitCode() != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestScannerErrorExitTwoEvenInAudit(t *testing.T) {
	for _, mode := range []string{"enforce", "audit"} {
		cfg := Defaults()
		cfg.Mode = mode
		r := finding.Result{Scanners: []finding.ScannerRun{{Name: "osv", Status: "error", Error: "boom"}, {Name: "g", Status: "skipped"}}}
		d := Evaluate(r, cfg, false, evalNow)
		if d.ExitCode() != 2 || d.Result != "fail" || len(d.ScannerErrors) != 1 {
			t.Fatalf("%s: %+v", mode, d)
		}
	}
}

func TestLicenseDenyBlocks(t *testing.T) {
	cfg := Defaults()
	cfg.Policy.FailOn[finding.CategorySCA] = Threshold{Severity: finding.Info}
	cfg.Scanners.SCA.Licenses.Deny = []string{"AGPL-3.0-only"}
	denied := fnd("license:agpl-3.0-only", finding.CategorySCA, finding.Info, false)
	allowed := fnd("license:MIT", finding.CategorySCA, finding.Info, false)
	d := Evaluate(res(denied, allowed), cfg, false, evalNow)
	if len(d.Blocking) != 1 || d.Blocking[0].ID != denied.ID {
		t.Fatalf("%+v", d.Blocking)
	}
	// Denied license still must pass the threshold check.
	cfg.Policy.FailOn[finding.CategorySCA] = Threshold{Severity: finding.High}
	if d := Evaluate(res(denied), cfg, false, evalNow); len(d.Blocking) != 0 {
		t.Fatal("threshold must also hold")
	}
}
