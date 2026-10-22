//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/ci/tools"
)

const releaseFixturesDir = "testdata/release"

// releaseTag is the version the fixture repositories carry at HEAD, so the
// version step takes the re-run path and no shiptag token is needed.
const releaseTag = "v0.1.0"

type releaseStep struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type releaseResult struct {
	Released    bool          `json:"released"`
	Tag         string        `json:"tag"`
	Image       string        `json:"image"`
	ImageDigest string        `json:"image_digest"`
	Steps       []releaseStep `json:"steps"`
}

type imageFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
}

func (r releaseResult) step(t *testing.T, name string) releaseStep {
	t.Helper()
	for _, s := range r.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("result.json has no %s step: %+v", name, r.Steps)
	return releaseStep{}
}

// releaseEnv is the environment of the CLI under test: the host environment
// without CI, GitHub, sigstore and shipguard variables, so the run has no
// ambient OIDC identity and no output files, plus extra.
//
// With token, SIGSTORE_ID_TOKEN is set to a value cosign cannot use. Without any identity
// cosign starts its interactive device flow and waits five minutes for a
// browser sign-in; an unusable token makes it fail at once, which is the
// outcome of a run without OIDC that the test is after.
func releaseEnv(token bool, extra ...string) []string {
	var env []string
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		switch {
		case k == "CI", strings.HasPrefix(k, "GITHUB_"), strings.HasPrefix(k, "ACTIONS_"),
			strings.HasPrefix(k, "RUNNER_"), strings.HasPrefix(k, "SIGSTORE_"),
			strings.HasPrefix(k, "COSIGN_"), strings.HasPrefix(k, "SHIPGUARD_"):
		default:
			env = append(env, e)
		}
	}
	if token {
		env = append(env, "SIGSTORE_ID_TOKEN=not-a-token")
	}
	return append(env, extra...)
}

// startRegistry runs registry:2 on a free local port and returns host:port.
func startRegistry(t *testing.T) string {
	t.Helper()
	id, code := docker(t, "run", "-d", "--rm", "-p", "127.0.0.1::5000", "registry:2")
	if code != 0 {
		t.Fatalf("docker run registry:2: %s", id)
	}
	id = strings.TrimSpace(id)
	t.Cleanup(func() { docker(t, "rm", "-f", id) })
	out, code := docker(t, "port", id, "5000/tcp")
	if code != 0 {
		t.Fatalf("docker port: %s", out)
	}
	// "127.0.0.1:32768" (and a second line for IPv6 when published there too)
	_, port, ok := strings.Cut(strings.Fields(out)[0], ":")
	if !ok {
		t.Fatalf("cannot parse docker port output %q", out)
	}
	addr := "localhost:" + port
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/v2/")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return addr
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("registry at %s is not ready: %v", addr, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// createBuilder makes a docker-container buildx builder (the default docker
// driver cannot export OCI layouts with attestations) and returns its name.
func createBuilder(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("shipguard-e2e-%d", os.Getpid())
	if out, code := docker(t, "buildx", "create", "--name", name, "--driver", "docker-container"); code != 0 {
		t.Fatalf("docker buildx create: %s", out)
	}
	t.Cleanup(func() { docker(t, "buildx", "rm", "--force", name) })
	return name
}

// pinnedCrane returns the crane that shipguard pins, from the shared tool cache.
func pinnedCrane(t *testing.T, cache string) string {
	t.Helper()
	specs, _, err := tools.Load()
	if err != nil {
		t.Fatal(err)
	}
	c := &tools.Cache{Dir: filepath.Join(cache, "tools"), Arch: runtime.GOARCH}
	bin, err := c.Ensure(context.Background(), specs["crane"])
	if err != nil {
		t.Fatalf("pinned crane: %v", err)
	}
	return bin
}

// releaseRepo copies the fixture into a git repo whose HEAD carries releaseTag
// and writes the config that points the image at the local registry. The
// shared cache (pinned tools and the trivy database) is linked in as
// .shipguard-cache, so it is downloaded once for all cases.
func releaseRepo(t *testing.T, fixture, registry, cache string) string {
	t.Helper()
	dir := t.TempDir()
	copyDir(t, filepath.Join(releaseFixturesDir, fixture), dir)
	cfg := fmt.Sprintf("release:\n  image:\n    name: %s/e2e/%s\n    platforms: [linux/amd64]\n", registry, fixture)
	if err := os.WriteFile(filepath.Join(dir, ".shipguard.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cache, filepath.Join(dir, ".shipguard-cache")); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	// The cache link is untracked state, not part of the commit.
	if err := os.WriteFile(filepath.Join(dir, ".git", "info", "exclude"), []byte(".shipguard-cache\n.shipguard/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAll(t, dir, "fixture")
	git(t, dir, "tag", releaseTag)
	return dir
}

// runRelease runs `shipguard release image` in dir and returns the combined
// output, the exit code and the parsed result.json.
func runRelease(t *testing.T, bin, dir, builder string, args ...string) (string, int, releaseResult) {
	t.Helper()
	return runReleaseWith(t, bin, dir, releaseEnv(true, "BUILDX_BUILDER="+builder), args...)
}

// runReleaseNoOIDC is runRelease without any identity in the environment.
func runReleaseNoOIDC(t *testing.T, bin, dir, builder string, args ...string) (string, int, releaseResult) {
	t.Helper()
	return runReleaseWith(t, bin, dir, releaseEnv(false, "BUILDX_BUILDER="+builder), args...)
}

func runReleaseWith(t *testing.T, bin, dir string, env []string, args ...string) (string, int, releaseResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append([]string{"release", "image"}, args...)...)
	cmd.Dir = dir
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("shipguard release image: %v", err)
	}
	t.Logf("shipguard release image %s: exit %d in %s", strings.Join(args, " "), code, time.Since(start).Round(time.Second))
	raw, rerr := os.ReadFile(filepath.Join(dir, ".shipguard", "release", "result.json"))
	if rerr != nil {
		t.Fatalf("result.json: %v (exit %d)\n%s", rerr, code, out.String())
	}
	var res releaseResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("parse result.json: %v", err)
	}
	return out.String(), code, res
}

// craneRun runs the pinned crane and returns stdout and whether it succeeded;
// stderr is returned in the second string.
func craneRun(t *testing.T, crane string, args ...string) (stdout, stderr string, ok bool) {
	t.Helper()
	cmd := exec.Command(crane, args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	return strings.TrimSpace(o.String()), strings.TrimSpace(e.String()), err == nil
}

var absentErrRe = regexp.MustCompile(`(?i)status code 404|manifest_unknown|name_unknown`)

// wantAbsent fails unless ref does not exist in the registry (and the registry
// answered, so an unreachable one cannot pass for "nothing pushed").
func wantAbsent(t *testing.T, crane, ref string) {
	t.Helper()
	out, errOut, ok := craneRun(t, crane, "digest", ref)
	if ok {
		t.Fatalf("crane digest %s = %s, want the tag to be absent", ref, out)
	}
	if !absentErrRe.MatchString(errOut) {
		t.Fatalf("crane digest %s failed for another reason: %s", ref, errOut)
	}
}

// publishedDigest returns the digest of ref, which must exist.
func publishedDigest(t *testing.T, crane, ref string) string {
	t.Helper()
	out, errOut, ok := craneRun(t, crane, "digest", ref)
	if !ok {
		t.Fatalf("crane digest %s: %s", ref, errOut)
	}
	return out
}

func releaseTags(version string) []string {
	parts := strings.Split(version, ".")
	return []string{"v" + version, version, "v" + parts[0] + "." + parts[1], "v" + parts[0]}
}

func TestReleaseImage(t *testing.T) {
	if os.Getenv("SHIPGUARD_RELEASE_E2E") == "" {
		t.Skip("SHIPGUARD_RELEASE_E2E is not set (run make release-e2e)")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the pinned release tools are linux-only; run on Linux or in a Linux container")
	}
	// The CLI runs on this host, so build it for the host.
	bin := filepath.Join(t.TempDir(), "shipguard")
	build := exec.Command("go", "build", "-o", bin, "./cmd/shipguard")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// SHIPGUARD_RELEASE_E2E_CACHE keeps the pinned tools and the trivy
	// database between runs (CI caches it).
	cache := os.Getenv("SHIPGUARD_RELEASE_E2E_CACHE")
	if cache == "" {
		cache = t.TempDir()
	}
	cache, err := filepath.Abs(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}

	registry := startRegistry(t)
	builder := createBuilder(t)
	crane := pinnedCrane(t, cache)

	clean := releaseRepo(t, "clean", registry, cache)
	cleanImage := registry + "/e2e/clean"
	version := strings.TrimPrefix(releaseTag, "v")

	// A dry run builds and scans but pushes nothing.
	t.Run("clean dry run", func(t *testing.T) {
		out, code, res := runRelease(t, bin, clean, builder, "--dry-run")
		if code != 0 {
			t.Fatalf("exit = %d, want 0\n%s", code, out)
		}
		if s := res.step(t, "image"); s.Status != "passed" || s.Reason != "dry run" {
			t.Errorf("image step = %+v, want passed (dry run)", s)
		}
		if res.Released {
			t.Error("a dry run reported released=true")
		}
		for _, tag := range releaseTags(version) {
			wantAbsent(t, crane, cleanImage+":"+tag)
		}
	})

	// Without an identity the step stops before the push, after the gate.
	t.Run("clean without OIDC stops before the push", func(t *testing.T) {
		out, code, res := runReleaseNoOIDC(t, bin, clean, builder)
		if code != 1 {
			t.Fatalf("exit = %d, want 1\n%s", code, out)
		}
		if s := res.step(t, "image"); s.Status != "failed" || !strings.Contains(s.Reason, "signing needs an OIDC identity") {
			t.Fatalf("image step = %+v, want failed with the OIDC reason\n%s", s, out)
		}
		for _, tag := range releaseTags(version) {
			wantAbsent(t, crane, cleanImage+":"+tag)
		}
	})

	t.Run("vulnerable image is blocked without OIDC", func(t *testing.T) {
		vuln := releaseRepo(t, "vuln", registry, cache)
		out, code, res := runReleaseNoOIDC(t, bin, vuln, builder)
		if code != 1 {
			t.Fatalf("exit = %d, want 1\n%s", code, out)
		}
		if s := res.step(t, "image"); s.Status != "blocked" {
			t.Fatalf("image step = %+v, want blocked (the gate runs before the identity check)\n%s", s, out)
		}
		for _, tag := range releaseTags(version) {
			wantAbsent(t, crane, registry+"/e2e/vuln:"+tag)
		}
	})

	// The image is pushed and tagged, then signing fails: the token is unusable.
	var firstDigest string
	t.Run("clean release fails at signing", func(t *testing.T) {
		out, code, res := runRelease(t, bin, clean, builder)
		if code != 1 {
			t.Fatalf("exit = %d, want 1\n%s", code, out)
		}
		if s := res.step(t, "image"); s.Status != "failed" || !strings.Contains(s.Reason, "cosign sign") {
			t.Fatalf("image step = %+v, want failed at cosign sign\n%s", s, out)
		}
		firstDigest = publishedDigest(t, crane, cleanImage+":"+releaseTag)
		t.Logf("published %s:{%s} = %s", cleanImage, strings.Join(releaseTags(version), ","), firstDigest)
		for _, tag := range releaseTags(version) {
			if got := publishedDigest(t, crane, cleanImage+":"+tag); got != firstDigest {
				t.Errorf("tag %s = %s, want %s", tag, got, firstDigest)
			}
		}
		checkPushedIndex(t, crane, cleanImage+":"+releaseTag)
	})

	// The same release again: the digest is the published one, so nothing is
	// pushed (a push would move the tag), and signing fails the same way.
	t.Run("clean rerun skips the push", func(t *testing.T) {
		if firstDigest == "" {
			t.Skip("the first release did not publish")
		}
		out, code, res := runRelease(t, bin, clean, builder)
		if code != 1 {
			t.Fatalf("exit = %d, want 1\n%s", code, out)
		}
		s := res.step(t, "image")
		if s.Status != "failed" || !strings.Contains(s.Reason, "cosign sign") {
			t.Fatalf("image step = %+v, want failed at cosign sign\n%s", s, out)
		}
		if !strings.Contains(out, "already published with the same images; keeping "+firstDigest) {
			t.Errorf("no skip line for the published digest in the output\n%s", out)
		}
		if !strings.Contains(out, firstDigest) {
			t.Errorf("the published digest %s is not the one signed\n%s", firstDigest, out)
		}
		for _, tag := range releaseTags(version) {
			if got := publishedDigest(t, crane, cleanImage+":"+tag); got != firstDigest {
				t.Errorf("tag %s = %s after the rerun, want %s", tag, got, firstDigest)
			}
		}
	})

	t.Run("vulnerable image is blocked", func(t *testing.T) {
		vuln := releaseRepo(t, "vuln", registry, cache)
		vulnImage := registry + "/e2e/vuln"
		out, code, res := runRelease(t, bin, vuln, builder)
		if code != 1 {
			t.Fatalf("exit = %d, want 1\n%s", code, out)
		}
		if s := res.step(t, "image"); s.Status != "blocked" {
			t.Fatalf("image step = %+v, want blocked\n%s", s, out)
		}
		for _, tag := range releaseTags(version) {
			wantAbsent(t, crane, vulnImage+":"+tag)
		}
		raw, err := os.ReadFile(filepath.Join(vuln, ".shipguard", "release", "image-findings.json"))
		if err != nil {
			t.Fatal(err)
		}
		var fs struct {
			Findings []imageFinding `json:"findings"`
		}
		if err := json.Unmarshal(raw, &fs); err != nil {
			t.Fatal(err)
		}
		t.Logf("blocked with %d image findings", len(fs.Findings))
		if !slices.ContainsFunc(fs.Findings, func(f imageFinding) bool { return f.Severity == "critical" }) {
			t.Errorf("image-findings.json has no critical finding: %s", raw)
		}
	})
}

// checkPushedIndex asserts that ref is an image index of the platform image
// and its attestations, not an index nested in another index.
func checkPushedIndex(t *testing.T, crane, ref string) {
	t.Helper()
	out, errOut, ok := craneRun(t, crane, "manifest", ref)
	if !ok {
		t.Fatalf("crane manifest %s: %s", ref, errOut)
	}
	var idx struct {
		MediaType string `json:"mediaType"`
		Manifests []struct {
			MediaType   string            `json:"mediaType"`
			Annotations map[string]string `json:"annotations"`
			Platform    struct {
				OS, Architecture string
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal([]byte(out), &idx); err != nil {
		t.Fatalf("parse manifest: %v\n%s", err, out)
	}
	if !strings.HasSuffix(idx.MediaType, "index.v1+json") && !strings.HasSuffix(idx.MediaType, "manifest.list.v2+json") {
		t.Fatalf("%s is a %q, want an image index\n%s", ref, idx.MediaType, out)
	}
	var image, attestation bool
	for _, m := range idx.Manifests {
		if strings.HasSuffix(m.MediaType, "index.v1+json") || strings.HasSuffix(m.MediaType, "manifest.list.v2+json") {
			t.Errorf("%s nests an index: %s", ref, out)
		}
		if m.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			attestation = true
		} else if m.Platform.OS == "linux" && m.Platform.Architecture == "amd64" {
			image = true
		}
	}
	if !image || !attestation {
		t.Errorf("%s has image=%v attestation=%v, want both\n%s", ref, image, attestation, out)
	}
}
