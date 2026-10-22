package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faridlamaul/shipguard/internal/release"
)

// relExec fakes shiptag, git, docker, trivy and crane (the version tag is absent) for the release command.
type relExec struct {
	shiptag string // contents written to --output-file
	trivy   string
	calls   []string
	cranes  []string // crane subcommands
}

func (f *relExec) Run(_ context.Context, _ string, _ []string, _ io.Writer, name string, args ...string) ([]byte, error) {
	base := filepath.Base(name)
	f.calls = append(f.calls, base)
	switch base {
	case "shiptag":
		for i, a := range args {
			if a == "--output-file" {
				_ = os.WriteFile(args[i+1], []byte(f.shiptag), 0o600)
			}
		}
	case "git":
		if args[0] == "rev-parse" {
			return nil, nil
		}
	case "docker":
		for i, a := range args {
			if a == "--output" {
				dest := strings.TrimSuffix(strings.TrimPrefix(args[i+1], "type=oci,dest="), ",tar=false")
				_ = os.MkdirAll(dest, 0o700)
				idx := `{"manifests":[{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}]}`
				_ = os.WriteFile(filepath.Join(dest, "index.json"), []byte(idx), 0o600)
			}
		}
	case "trivy":
		return []byte(f.trivy), nil
	case "crane":
		f.cranes = append(f.cranes, args[0])
		if args[0] == "digest" {
			return nil, errors.New("MANIFEST_UNKNOWN: manifest unknown")
		}
	}
	return nil, nil
}

func releaseSetup(t *testing.T, f *relExec) string {
	t.Helper()
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	oldE, oldT := releaseExec, releaseToolResolver
	releaseExec = f
	releaseToolResolver = func(string) (func(context.Context, string) (string, error), map[string]string, error) {
		return func(_ context.Context, n string) (string, error) { return "/tools/" + n, nil }, map[string]string{}, nil
	}
	t.Cleanup(func() { releaseExec, releaseToolResolver = oldE, oldT })
	return dir
}

func runRelease(dir string, env map[string]string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := execute(context.Background(), append([]string{"release", "--dir", dir}, args...), envOf(env), &out, &errb)
	return code, out.String(), errb.String()
}

func TestReleaseCmdUnknownStep(t *testing.T) {
	dir := releaseSetup(t, &relExec{})
	code, _, errb := runRelease(dir, nil, "deploy")
	if code != 2 || !strings.Contains(errb, "deploy") {
		t.Fatalf("code=%d stderr=%s", code, errb)
	}
}

func TestReleaseCmdNothingToRelease(t *testing.T) {
	f := &relExec{shiptag: "released=false\n"}
	dir := releaseSetup(t, f)
	outFile := filepath.Join(t.TempDir(), "gh-out")
	code, _, errb := runRelease(dir, map[string]string{"GITHUB_OUTPUT": outFile})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errb)
	}
	b, _ := os.ReadFile(outFile)
	if !strings.Contains(string(b), "released=false\n") {
		t.Fatalf("outputs = %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, ".shipguard", "release", "result.json")); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseCmdBlocked(t *testing.T) {
	f := &relExec{
		shiptag: "released=true\ntag=v1.4.0\n",
		trivy:   `{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2026-9999","PkgName":"openssl","InstalledVersion":"3.0","FixedVersion":"3.1","Severity":"CRITICAL","Title":"bad"}]}]}`,
	}
	dir := releaseSetup(t, f)
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "release:\n  image:\n    name: ghcr.io/o/app\n    platforms: [linux/amd64]\n"
	if err := os.WriteFile(filepath.Join(dir, ".shipguard.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errb := runRelease(dir, nil)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, errb)
	}
	sum, err := os.ReadFile(filepath.Join(dir, ".shipguard", "release", "summary.md"))
	if err != nil || !strings.Contains(string(sum), "CVE-2026-9999") {
		t.Fatalf("summary = %s (%v)", sum, err)
	}
	for _, c := range f.calls {
		if c == "cosign" {
			t.Fatalf("signed a blocked image: %v", f.calls)
		}
	}
	if strings.Join(f.cranes, " ") != "digest" {
		t.Fatalf("pushed or tagged a blocked image: %v", f.cranes)
	}
}

var _ release.Exec = (*relExec)(nil)

func TestReleaseCmdBadPrerelease(t *testing.T) {
	dir := releaseSetup(t, &relExec{})
	code, _, errb := runRelease(dir, nil, "--prerelease", "rc;rm")
	if code != 2 || !strings.Contains(errb, "--prerelease") {
		t.Fatalf("code=%d stderr=%s", code, errb)
	}
}

func TestReleaseNonLinuxMessage(t *testing.T) {
	fn, _, err := newToolResolverMsg(t.TempDir(), "darwin", "arm64", func(goos, goarch string) string {
		return "pinned release tools are only available on linux (running on " + goos + "/" + goarch + "); run shipguard release in a Linux CI runner"
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fn(context.Background(), "trivy")
	if err == nil || strings.Contains(err.Error(), "ci.steps") || !strings.Contains(err.Error(), "shipguard release") {
		t.Fatalf("err = %v", err)
	}
}

func TestReleaseToolCacheOutsideRepo(t *testing.T) {
	dir := releaseSetup(t, &relExec{shiptag: "released=false\n"})
	var got string
	inner := releaseToolResolver
	releaseToolResolver = func(cacheRoot string) (func(context.Context, string) (string, error), map[string]string, error) {
		got = cacheRoot
		return inner(cacheRoot)
	}
	rt := t.TempDir()
	if code, _, errb := runRelease(dir, map[string]string{"RUNNER_TEMP": rt}); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errb)
	}
	if want := filepath.Join(rt, "shipguard-cache"); got != want {
		t.Fatalf("tool cache root = %q, want %q", got, want)
	}
}
