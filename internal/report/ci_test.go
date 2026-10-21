package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/ci/run"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const junitA = `<?xml version="1.0"?>
<testsuites>
  <testsuite name="outer">
    <testsuite name="inner">
      <testcase name="TestOne" file="a_test.go" line="12"><failure message="boom">detail</failure></testcase>
      <testcase name="TestOk"/>
    </testsuite>
  </testsuite>
</testsuites>`

const junitB = `<testsuite name="solo"><testcase name="TestTwo"><error>first line
second</error></testcase></testsuite>`

func TestMergeJUnit(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "a.xml"), filepath.Join(d, "b.xml")
	writeFile(t, a, junitA)
	writeFile(t, b, junitB)
	var buf bytes.Buffer
	fs, err := MergeJUnit([]string{a, b}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	want := []TestFailure{
		{Suite: "inner", Name: "TestOne", File: "a_test.go", Line: 12, Message: "boom"},
		{Suite: "solo", Name: "TestTwo", Message: "first line"},
	}
	if len(fs) != 2 || fs[0] != want[0] || fs[1] != want[1] {
		t.Fatalf("failures = %+v", fs)
	}
	out := buf.String()
	if strings.Count(out, "<testsuites>") != 1 || !strings.Contains(out, `name="solo"`) || !strings.Contains(out, `name="outer"`) {
		t.Fatalf("merged = %s", out)
	}
}

func TestMergeJUnitEmpty(t *testing.T) {
	var buf bytes.Buffer
	if _, err := MergeJUnit(nil, &buf); err != nil || buf.String() != "<testsuites/>\n" {
		t.Fatalf("%q %v", buf.String(), err)
	}
}

func TestMergeJUnitMalformed(t *testing.T) {
	d := t.TempDir()
	bad := filepath.Join(d, "bad.xml")
	writeFile(t, bad, "<testsuite><testcase")
	_, err := MergeJUnit([]string{bad}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "bad.xml") {
		t.Fatalf("err = %v", err)
	}
}

func TestCollectJUnitMissingWarns(t *testing.T) {
	r := CIResult{Language: "go", Version: "1.22", Steps: []run.StepResult{{
		Name: ci.StepName("test"), Status: "passed",
		Warnings: []string{"no JUnit found for test (reports/*.xml)"},
	}}}
	s := CISummary(r, nil, 64<<10)
	if !strings.Contains(s, "no JUnit found for test (reports/*.xml)") {
		t.Fatal(s)
	}
	if !strings.HasPrefix(s, "## shipguard ci: go 1.22\n") {
		t.Fatal(s)
	}
}

func TestCISummaryCoverageAndTruncates(t *testing.T) {
	d := t.TempDir()
	cov := filepath.Join(d, "cov.xml")
	writeFile(t, cov, `<coverage line-rate="0.8567"></coverage>`)
	r := CIResult{Language: "go", Version: "1", Steps: []run.StepResult{
		{Name: "test", Status: "failed", Reason: "exit 1", Duration: 2 * time.Second, Coverage: cov},
	}}
	var fs []TestFailure
	for i := 0; i < 25; i++ {
		fs = append(fs, TestFailure{Suite: "s", Name: fmt.Sprintf("T%d", i), File: "f.go", Line: i + 1, Message: "m"})
	}
	s := CISummary(r, fs, 64<<10)
	if !strings.Contains(s, "Coverage: 85.7%") || !strings.Contains(s, "5 more in .shipguard/ci/result.json") {
		t.Fatal(s)
	}
	if strings.Count(s, "- s › T") != 20 {
		t.Fatal(s)
	}
	small := CISummary(r, fs, 300)
	if len(small) > 300 || !strings.Contains(small, "more in .shipguard/ci/result.json") {
		t.Fatalf("len %d\n%s", len(small), small)
	}
	tiny := CISummary(r, fs, 40)
	if len(tiny) > 40 {
		t.Fatalf("len %d", len(tiny))
	}
}

func TestCIGitHubAnnotations(t *testing.T) {
	d := t.TempDir()
	sum := filepath.Join(d, "sum.md")
	env := map[string]string{"GITHUB_STEP_SUMMARY": sum}
	var fs []TestFailure
	for i := 0; i < 60; i++ {
		fs = append(fs, TestFailure{Suite: "s", Name: "n", File: "a,b:c.go", Line: 3, Message: "100%\r\nx"})
	}
	var out bytes.Buffer
	r := CIResult{Language: "go", Version: "1"}
	if err := CIGitHub(r, fs, func(k string) string { return env[k] }, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 50 {
		t.Fatalf("lines = %d", len(lines))
	}
	want := "::error file=a%2Cb%3Ac.go,line=3,title=s › n::100%25%0D%0Ax"
	if lines[0] != want {
		t.Fatalf("got %q\nwant %q", lines[0], want)
	}
	b, err := os.ReadFile(sum)
	if err != nil || !strings.Contains(string(b), "## shipguard ci: go 1") {
		t.Fatalf("%q %v", b, err)
	}
}

func ciFixture(t *testing.T, dir string) CIResult {
	t.Helper()
	writeFile(t, filepath.Join(dir, "reports/a.xml"), junitA)
	writeFile(t, filepath.Join(dir, "cov/cobertura.xml"), `<coverage line-rate="0.5"/>`)
	return CIResult{Language: "go", Version: "1", Source: "auto", Steps: []run.StepResult{
		{Name: "test", Status: "failed", Reason: "exit 1", JUnit: []string{"reports/a.xml"}, Coverage: "cov/cobertura.xml"},
	}}
}

func TestWriteCIFiles(t *testing.T) {
	dir := t.TempDir()
	r := ciFixture(t, dir)
	if err := WriteCI(dir, r); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, ".shipguard", "ci")
	var got CIResult
	b, err := os.ReadFile(filepath.Join(base, "result.json"))
	if err != nil || json.Unmarshal(b, &got) != nil || got.Language != "go" || len(got.Steps) != 1 {
		t.Fatalf("result.json %s %v", b, err)
	}
	s, _ := os.ReadFile(filepath.Join(base, "summary.md"))
	if !strings.Contains(string(s), "Coverage: 50.0%") || !strings.Contains(string(s), "TestOne") {
		t.Fatalf("summary %s", s)
	}
	j, _ := os.ReadFile(filepath.Join(base, "test-results", "junit.xml"))
	if !strings.Contains(string(j), "<testsuites>") {
		t.Fatalf("junit %s", j)
	}
	c, _ := os.ReadFile(filepath.Join(base, "coverage.xml"))
	if string(c) != `<coverage line-rate="0.5"/>` {
		t.Fatalf("coverage %s", c)
	}
	if _, err := os.Stat(filepath.Join(dir, "test-results", "junit.xml")); err == nil {
		t.Fatal("root copy written outside Bitbucket")
	}
}

func TestWriteCINoJUnit(t *testing.T) {
	dir := t.TempDir()
	if err := WriteCI(dir, CIResult{Language: "go"}); err != nil {
		t.Fatal(err)
	}
	j, _ := os.ReadFile(filepath.Join(dir, ".shipguard/ci/test-results/junit.xml"))
	if strings.TrimSpace(string(j)) != "<testsuites/>" {
		t.Fatalf("%s", j)
	}
	if _, err := os.Stat(filepath.Join(dir, ".shipguard/ci/coverage.xml")); err == nil {
		t.Fatal("coverage.xml without coverage")
	}
}

func TestWriteCIBitbucketNoRootCopy(t *testing.T) {
	// Bitbucket scans hidden directories, so a clone-root copy would double-count.
	dir, clone := t.TempDir(), t.TempDir()
	r := ciFixture(t, dir)
	t.Setenv("BITBUCKET_BUILD_NUMBER", "1")
	t.Setenv("BITBUCKET_CLONE_DIR", clone)
	if err := WriteCI(dir, r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(clone, "test-results", "junit.xml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clone-root junit.xml must not be written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".shipguard", "ci", "test-results", "junit.xml")); err != nil {
		t.Fatal(err)
	}
}

func TestWriteCITruncatedJUnitWarns(t *testing.T) {
	dir := t.TempDir()
	r := ciFixture(t, dir)
	writeFile(t, filepath.Join(dir, "reports/bad.xml"), "<testsuite><testcase")
	r.Steps[0].JUnit = []string{"reports/a.xml", "reports/bad.xml", "reports/missing.xml", "reports/a.xml"}
	if err := WriteCI(dir, r); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, ".shipguard", "ci")
	for _, f := range []string{"result.json", "summary.md", "test-results/junit.xml", "coverage.xml"} {
		if _, err := os.Stat(filepath.Join(base, f)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := os.ReadFile(filepath.Join(base, "summary.md"))
	if !strings.Contains(string(s), "unreadable JUnit reports/bad.xml") || !strings.Contains(string(s), "unreadable JUnit reports/missing.xml") || !strings.Contains(string(s), "TestOne") {
		t.Fatalf("summary %s", s)
	}
	j, _ := os.ReadFile(filepath.Join(base, "test-results", "junit.xml"))
	if strings.Count(string(j), `name="outer"`) != 1 {
		t.Fatalf("junit %s", j)
	}
	if len(r.Steps[0].Warnings) != 0 {
		t.Fatal("caller's result mutated")
	}
}

func TestReadCappedTooLarge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.xml")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(ciMaxFile + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := readCapped(p); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
	if _, err := MergeJUnit([]string{p}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "big.xml") {
		t.Fatalf("err = %v", err)
	}
}

func TestMergeJUnitTruncatesMessage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.xml")
	writeFile(t, p, `<testsuite name="s"><testcase name="t"><failure message="`+strings.Repeat("é", 5000)+`"/></testcase></testsuite>`)
	fs, err := MergeJUnit([]string{p}, &bytes.Buffer{})
	if err != nil || len(fs) != 1 || len(fs[0].Message) > ciMaxMessage || !utf8.ValidString(fs[0].Message) {
		t.Fatalf("%v len=%d", err, len(fs[0].Message))
	}
}

func TestCIGitHubUsesDir(t *testing.T) {
	dir := t.TempDir()
	r := ciFixture(t, dir)
	r.Dir = dir
	sum := filepath.Join(t.TempDir(), "sum.md")
	if err := CIGitHub(r, nil, func(k string) string {
		if k == "GITHUB_STEP_SUMMARY" {
			return sum
		}
		return ""
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(sum)
	if !strings.Contains(string(b), "Coverage: 50.0%") {
		t.Fatalf("%s", b)
	}
}

func TestWriteCIRemovesStaleCoverage(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".shipguard/ci/coverage.xml")
	writeFile(t, stale, "old")
	if err := WriteCI(dir, CIResult{Language: "go"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("stale coverage.xml kept")
	}
}

func TestMergeJUnitBareTestcases(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "node.xml")
	writeFile(t, p, `<?xml version="1.0"?>
<testsuites>
  <testcase name="passes" time="0.1"/>
  <testcase name="fails" file="x.js" line="4"><failure message="nope"/></testcase>
  <testsuite name="kept"><testcase name="inner"><failure message="in"/></testcase></testsuite>
</testsuites>`)
	var buf bytes.Buffer
	fs, err := MergeJUnit([]string{p}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	want := []TestFailure{
		{Suite: "kept", Name: "inner", Message: "in"},
		{Suite: "node.xml", Name: "fails", File: "x.js", Line: 4, Message: "nope"},
	}
	if len(fs) != 2 || fs[0] != want[0] || fs[1] != want[1] {
		t.Fatalf("failures = %+v", fs)
	}
	out := buf.String()
	if !strings.Contains(out, `<testsuite name="node.xml">`) || !strings.Contains(out, `name="passes"`) || !strings.Contains(out, `name="kept"`) || out == "<testsuites/>\n" {
		t.Fatalf("merged = %s", out)
	}
	if _, _, err := parseJUnit("n", []byte(out)); err != nil {
		t.Fatalf("merged output not parseable: %v", err)
	}
}
