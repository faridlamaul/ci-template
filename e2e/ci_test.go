//go:build e2e

package e2e

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const ciFixturesDir = "../testdata/ci"

// ciImages are the official language images, overridable per key with
// SHIPGUARD_CI_IMAGE_<KEY> (for example SHIPGUARD_CI_IMAGE_GO=golang:1.27).
// node25 is a Node >= 25 image, which ships without corepack.
var ciImages = map[string]string{
	"go":     "golang:1.27",
	"node":   "node:24",
	"node25": "node:26",
	"python": "python:3.13",
	"ruby":   "ruby:3.4",
	"rust":   "rust:1",
}

// ciLintFinding is text the linter prints for the fail-lint fixture of each
// language, so a lint step that dies for another reason does not pass the case.
var ciLintFinding = map[string]string{
	"go":     "unused",
	"node":   "remove the marker comment",
	"python": "F401",
	"ruby":   "Lint/UselessAssignment",
	"rust":   "needless_return",
}

// ciBuild is the expected build outcome per language: "passed", or the exact
// skip reason (the fixtures have no build script, gemspec or build-system).
var ciBuild = map[string]string{
	"go":     "passed",
	"node":   "no build script in package.json",
	"python": "no [build-system] in pyproject.toml",
	"ruby":   "no gemspec",
	"rust":   "passed",
}

type ciCase struct {
	lang, name string // fixture dir: testdata/ci/<lang>/<name>
	kind       string // pass | fail-lint | fail-test
	image      string // ciImages key; empty = lang
	wantOut    string // text the output must contain (proves the package manager ran)
}

func (c ciCase) imageKey() string {
	if c.image != "" {
		return c.image
	}
	return c.lang
}

var ciCases = func() []ciCase {
	var cs []ciCase
	for _, l := range []string{"go", "node", "python", "ruby", "rust"} {
		for _, k := range []string{"pass", "fail-lint", "fail-test"} {
			cs = append(cs, ciCase{lang: l, name: k, kind: k})
		}
	}
	return append(cs,
		ciCase{lang: "python", name: "pass-uv", kind: "pass"},
		ciCase{lang: "node", name: "pass-bun", kind: "pass", wantOut: "bun install v"},
		ciCase{lang: "node", name: "pass-pnpm", kind: "pass", wantOut: "pnpm"},
		// npm's "added 1 package" proves the corepack bootstrap ran.
		ciCase{lang: "node", name: "pass-pnpm", kind: "pass", image: "node25", wantOut: "added 1 package"},
	)
}()

type ciStep struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Reason   string   `json:"reason"`
	ExitCode int      `json:"exit_code"`
	JUnit    []string `json:"junit"`
}

type ciResult struct {
	Language string   `json:"language"`
	Version  string   `json:"version"`
	Steps    []ciStep `json:"steps"`
}

func (r ciResult) step(t *testing.T, name string) ciStep {
	t.Helper()
	for _, s := range r.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("result.json has no %s step: %+v", name, r.Steps)
	return ciStep{}
}

// ciSelected reports whether lang is selected by SHIPGUARD_CI_E2E_LANG, a
// comma-separated list of languages (empty selects all).
func ciSelected(lang string) bool {
	v := strings.TrimSpace(os.Getenv("SHIPGUARD_CI_E2E_LANG"))
	if v == "" {
		return true
	}
	for _, l := range strings.Split(v, ",") {
		if strings.TrimSpace(l) == lang {
			return true
		}
	}
	return false
}

func ciImage(key string) string {
	if v := os.Getenv("SHIPGUARD_CI_IMAGE_" + strings.ToUpper(key)); v != "" {
		return v
	}
	return ciImages[key]
}

// buildLinuxBinary builds shipguard for the Docker server's platform: the
// pinned tools it downloads are Linux-only.
func buildLinuxBinary(t *testing.T) string {
	t.Helper()
	arch, err := exec.Command("docker", "version", "--format", "{{.Server.Arch}}").Output()
	if err != nil {
		t.Fatalf("docker version: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "shipguard")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/shipguard")
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+strings.TrimSpace(string(arch)), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// junitCounts returns the number of test cases and failures (failed or
// errored) in a JUnit file, however the suites are nested.
func junitCounts(t *testing.T, path string) (cases, failures int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("junit.xml: %v", err)
	}
	defer f.Close()
	dec := xml.NewDecoder(f)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return cases, failures
		}
		if err != nil {
			t.Fatalf("parse junit.xml: %v", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			switch se.Name.Local {
			case "testcase":
				cases++
			case "failure", "error":
				failures++
			}
		}
	}
}

func TestCIFixtures(t *testing.T) {
	if os.Getenv("SHIPGUARD_CI_E2E") == "" {
		t.Skip("SHIPGUARD_CI_E2E is not set (run make ci-e2e)")
	}
	selected := 0
	for _, c := range ciCases {
		if ciSelected(c.lang) {
			selected++
		}
	}
	if selected == 0 {
		t.Fatalf("SHIPGUARD_CI_E2E_LANG=%q matches no language", os.Getenv("SHIPGUARD_CI_E2E_LANG"))
	}
	bin := buildLinuxBinary(t)
	// Serial on purpose: the cases download toolchain components and tools.
	for _, c := range ciCases {
		if !ciSelected(c.lang) {
			continue
		}
		name := c.lang + "/" + c.name
		if c.image != "" {
			name += "@" + c.image
		}
		t.Run(name, func(t *testing.T) {
			runCICase(t, bin, c)
		})
	}
}

func runCICase(t *testing.T, bin string, c ciCase) {
	img := ciImage(c.imageKey())
	dir := t.TempDir()
	// The container runs as root; make its output removable by the host user.
	t.Cleanup(func() {
		docker(t, "run", "--rm", "-v", dir+":/w", "--entrypoint", "sh", img, "-c", "chmod -R a+rwX /w")
	})
	copyDir(t, filepath.Join(ciFixturesDir, c.lang, c.name), dir)

	start := time.Now()
	out, code := docker(t, "run", "--rm", "-v", dir+":/w", "-w", "/w",
		"-v", bin+":/usr/local/bin/shipguard:ro", img, "shipguard", "ci")
	t.Logf("%s: exit %d in %s", img, code, time.Since(start).Round(time.Second))
	failed := func() {
		if t.Failed() {
			t.Logf("container output:\n%s", out)
		}
	}
	defer failed()

	raw, err := os.ReadFile(filepath.Join(dir, ".shipguard", "ci", "result.json"))
	if err != nil {
		t.Fatalf("result.json: %v (exit %d)", err, code)
	}
	var res ciResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("parse result.json: %v", err)
	}
	if res.Language != c.lang {
		t.Errorf("language = %q, want %q", res.Language, c.lang)
	}
	if strings.Contains(out, "requested but") {
		t.Errorf("toolchain version mismatch warning in output; fixture pin is stale")
	}
	if _, err := os.Stat(filepath.Join(dir, ".shipguard", "ci", "summary.md")); err != nil {
		t.Errorf("summary.md: %v", err)
	}

	junit := filepath.Join(dir, ".shipguard", "ci", "test-results", "junit.xml")
	wantCode, lint, test := 0, "passed", "passed"
	switch c.kind {
	case "fail-lint":
		wantCode, lint = 1, "failed"
	case "fail-test":
		wantCode, test = 1, "failed"
	}
	if code != wantCode {
		t.Errorf("exit = %d, want %d", code, wantCode)
	}
	if c.wantOut != "" && !strings.Contains(out, c.wantOut) {
		t.Errorf("output does not contain %q", c.wantOut)
	}
	if got := res.step(t, "install").Status; got != "passed" {
		t.Errorf("install = %s, want passed", got)
	}
	if got := res.step(t, "lint").Status; got != lint {
		t.Errorf("lint = %s, want %s", got, lint)
	}
	if got := res.step(t, "test").Status; got != test {
		t.Errorf("test = %s, want %s", got, test)
	}
	if c.kind == "fail-lint" {
		if ls := res.step(t, "lint"); ls.ExitCode <= 0 {
			t.Errorf("lint exit_code = %d, want the linter's finding code (> 0)", ls.ExitCode)
		}
		if want := ciLintFinding[c.lang]; !strings.Contains(out, want) {
			t.Errorf("output does not show the lint finding %q", want)
		}
	}
	b := res.step(t, "build")
	if want := ciBuild[c.lang]; want == "passed" {
		if b.Status != "passed" {
			t.Errorf("build = %s (%s), want passed", b.Status, b.Reason)
		}
	} else if b.Status != "skipped" || b.Reason != want {
		t.Errorf("build = %s (%q), want skipped (%q)", b.Status, b.Reason, want)
	}
	for _, s := range res.Steps {
		if !slices.Contains([]string{"passed", "failed", "skipped"}, s.Status) {
			t.Errorf("step %s: unexpected status %q", s.Name, s.Status)
		}
		if s.Status == "skipped" && s.Reason == "" {
			t.Errorf("step %s skipped without a reason", s.Name)
		}
		if c.kind == "pass" && s.Status == "failed" {
			t.Errorf("step %s failed on a passing fixture (%s)", s.Name, s.Reason)
		}
	}

	cases, failures := junitCounts(t, junit)
	if cases == 0 {
		t.Errorf("junit.xml has no test cases")
	}
	if c.kind == "fail-test" && failures < 1 {
		t.Errorf("junit.xml has %d failures, want at least 1", failures)
	}
	if c.kind != "fail-test" && failures != 0 {
		t.Errorf("junit.xml has %d failures, want 0", failures)
	}

	// Go and Python write coverage.xml only after the test commands succeed, so
	// the fail-test cases have none.
	if (c.lang == "go" || c.lang == "python") && c.kind != "fail-test" {
		f, err := os.Open(filepath.Join(dir, ".shipguard", "ci", "coverage.xml"))
		if err != nil {
			t.Fatalf("coverage.xml: %v", err)
		}
		defer f.Close()
		var cov struct {
			XMLName xml.Name `xml:"coverage"`
		}
		if err := xml.NewDecoder(f).Decode(&cov); err != nil {
			t.Errorf("coverage.xml does not parse: %v", err)
		}
	}
}
