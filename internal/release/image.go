package release

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/policy"
	"github.com/faridlamaul/shipguard/internal/scanner"
)

var pushedDigestRe = regexp.MustCompile(`@(sha256:[0-9a-fA-F]+)`)

// imageTags lists the tags for a version, the full vX.Y.Z first. A prerelease
// gets only the exact version, with and without the v.
func imageTags(version string) []string {
	tags := []string{"v" + version, version}
	if strings.Contains(version, "-") {
		return tags
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return tags
	}
	return append(tags, "v"+parts[0]+"."+parts[1], "v"+parts[0])
}

// usage marks a config problem: the step fails and Run returns the error (exit 2).
func usage(r *Result, format string, a ...any) StepResult {
	err := fmt.Errorf("%w: "+format, append([]any{policy.ErrConfig}, a...)...)
	r.usageErr = err
	return StepResult{Status: "failed", Reason: err.Error()}
}

func fail(format string, a ...any) StepResult {
	return StepResult{Status: "failed", Reason: fmt.Sprintf(format, a...)}
}

// layoutDigest returns the digest of the single manifest in an OCI layout.
func layoutDigest(layout string) (string, error) {
	data, err := os.ReadFile(filepath.Join(layout, "index.json"))
	if err != nil {
		return "", err
	}
	var idx struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(data, &idx); err != nil {
		return "", err
	}
	if len(idx.Manifests) != 1 || !strings.HasPrefix(idx.Manifests[0].Digest, "sha256:") {
		return "", fmt.Errorf("expected one manifest in index.json, found %d", len(idx.Manifests))
	}
	return idx.Manifests[0].Digest, nil
}

// tagAbsent reports whether crane's error says the manifest or repository does not exist.
func tagAbsent(msg string) bool { return absentRe.MatchString(msg) }

var absentRe = regexp.MustCompile(`(?i)manifest_unknown|name_unknown|status code 404|\b404 not found\b`)

// oneLine trims s, collapses whitespace and caps it at n characters.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// hasOIDC reports whether cosign can sign without an interactive sign-in: an
// explicit token, or the GitHub Actions OIDC endpoint. Without either it waits
// five minutes for a browser, after the image is already pushed.
func hasOIDC(getenv func(string) string) bool {
	if getenv("SIGSTORE_ID_TOKEN") != "" {
		return true
	}
	return getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" && getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}

const errNoOIDC = "signing needs an OIDC identity: grant `id-token: write` (GitHub) or set SIGSTORE_ID_TOKEN"

// pushWithRetry runs crane push up to three times, waiting 5s then 15s. The
// first push to a new ghcr package can be denied while the package is created.
func pushWithRetry(ctx context.Context, o Options, crane, layout, ref string) ([]byte, error) {
	sleep := o.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	waits := []time.Duration{5 * time.Second, 15 * time.Second}
	for attempt := 0; ; attempt++ {
		out, err := o.Exec.Run(ctx, o.Dir, nil, o.Out, crane, "push", layout, ref)
		if err == nil || attempt == len(waits) {
			return out, err
		}
		_, _ = fmt.Fprintf(o.Out, "crane push attempt %d failed, retrying in %s: %s\n", attempt+1, waits[attempt], oneLine(err.Error(), 300))
		sleep(waits[attempt])
	}
}

func image(ctx context.Context, o Options, r *Result) StepResult {
	cfg := o.Config.Release.Image
	if _, err := os.Stat(filepath.Join(o.Dir, cfg.Dockerfile)); err != nil {
		return StepResult{Status: "skipped", Reason: "no " + cfg.Dockerfile}
	}
	name := cfg.Name
	if name == "" {
		repo := o.Getenv("GITHUB_REPOSITORY")
		if repo == "" {
			return usage(r, "release.image.name is not set and GITHUB_REPOSITORY is empty")
		}
		name = "ghcr.io/" + strings.ToLower(repo)
	}
	if _, ok := cfg.BuildArgs["VERSION"]; ok {
		return usage(r, "release.image.build_args must not set VERSION; shipguard sets it")
	}
	r.Image = name

	trivy, err := o.Tool(ctx, "trivy")
	if err != nil {
		return fail("%v", err)
	}
	var crane, cosign string
	tags := imageTags(r.Version)
	ref := name + ":" + tags[0]
	if !o.DryRun {
		if crane, err = o.Tool(ctx, "crane"); err != nil {
			return fail("%v", err)
		}
		if cosign, err = o.Tool(ctx, "cosign"); err != nil {
			return fail("%v", err)
		}
		// A published version tag is never rebuilt: the re-run keeps that image.
		var digestLog bytes.Buffer // crane prints the registry error on stderr
		pub, err := o.Exec.Run(ctx, o.Dir, nil, &digestLog, crane, "digest", ref)
		switch {
		case err == nil:
			published := strings.TrimSpace(string(pub))
			_, _ = fmt.Fprintf(o.Out, "%s is already published as %s; scanning the published image\n", tags[0], published)
			return rerun(ctx, o, r, trivy, crane, cosign, name, published)
		case !tagAbsent(err.Error() + " " + digestLog.String()):
			return fail("cannot check existing tag: %v: %s", err, oneLine(digestLog.String(), 300))
		}
	}

	if _, err := o.Exec.Run(ctx, o.Dir, nil, io.Discard, "docker", "buildx", "version"); err != nil {
		return fail("docker buildx is not available; add docker/setup-buildx-action before shipguard release")
	}
	tmp, err := os.MkdirTemp("", "shipguard-image-")
	if err != nil {
		return fail("%v", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	layout := filepath.Join(tmp, "layout")

	args := []string{"buildx", "build",
		"--platform", strings.Join(cfg.Platforms, ","),
		"--provenance=mode=max", "--sbom=true",
		"--build-arg", "VERSION=" + r.Version}
	keys := make([]string, 0, len(cfg.BuildArgs))
	for k := range cfg.BuildArgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "--build-arg", k+"="+cfg.BuildArgs[k])
	}
	args = append(args, "--output", "type=oci,dest="+layout+",tar=false", "-f", cfg.Dockerfile, cfg.Context)
	if _, err := o.Exec.Run(ctx, o.Dir, nil, o.Out, "docker", args...); err != nil {
		return fail("docker buildx build: %v", err)
	}
	digest, err := layoutDigest(layout)
	if err != nil {
		return fail("read built image: %v", err)
	}

	cache := filepath.Join(o.CacheDir, "trivy")
	if s := gate(ctx, o, r, trivy, name, "nothing was pushed", func(p string) []string {
		return append([]string{"image", "--input", layout}, trivyArgs(cache, p)...)
	}); s != nil {
		return *s
	}
	if o.DryRun {
		return StepResult{Status: "passed", Reason: "dry run"}
	}

	// After the gate, so a blocked image is reported even without an identity.
	if !hasOIDC(o.Getenv) {
		return fail("%s; nothing was pushed", errNoOIDC)
	}

	// A one-entry layout pushes that entry, so the digest is manifests[0].digest.
	out, err := pushWithRetry(ctx, o, crane, layout, ref)
	if err != nil {
		return fail("crane push: %v", err)
	}
	m := pushedDigestRe.FindSubmatch(out)
	if m == nil {
		return fail("crane push printed no digest")
	}
	if string(m[1]) != digest {
		return fail("pushed digest does not match the scanned layout (%s != %s)", m[1], digest)
	}
	if s := tagAndSign(ctx, o, r, crane, cosign, ref, tags[1:], name+"@"+digest, digest); s != nil {
		return *s
	}
	return StepResult{Status: "passed", Reason: name + "@" + digest}
}

// rerun finishes a release whose version tag is already published: it scans the
// published image again, then re-applies every tag and signs it. Nothing is rebuilt.
func rerun(ctx context.Context, o Options, r *Result, trivy, crane, cosign, name, digest string) StepResult {
	pinned := name + "@" + digest
	cache := filepath.Join(o.CacheDir, "trivy")
	if s := gate(ctx, o, r, trivy, name, "nothing was tagged or signed", func(p string) []string {
		return append(append([]string{"image"}, trivyArgs(cache, p)...), pinned)
	}); s != nil {
		return *s
	}
	if !hasOIDC(o.Getenv) {
		return fail("%s; nothing was tagged or signed", errNoOIDC)
	}
	if s := tagAndSign(ctx, o, r, crane, cosign, pinned, imageTags(r.Version), pinned, digest); s != nil {
		return *s
	}
	return StepResult{Status: "passed", Reason: "re-run: kept the published image"}
}

func trivyArgs(cache, platform string) []string {
	return []string{"--platform", platform, "--scanners", "vuln", "--format", "json", "--cache-dir", cache}
}

// gate scans every platform (trivy gets argv(platform)), records the findings in r
// and applies the policy. It returns the step result when the scan failed or the
// image is blocked, else nil. untouched says what the block left alone.
func gate(ctx context.Context, o Options, r *Result, trivy, name, untouched string, argv func(platform string) []string) *StepResult {
	var findings []finding.Finding
	for _, p := range o.Config.Release.Image.Platforms {
		out, err := o.Exec.Run(ctx, o.Dir, nil, io.Discard, trivy, argv(p)...)
		if err != nil {
			s := fail("trivy (%s): %v", p, err)
			return &s
		}
		fs, err := scanner.ParseTrivyImage(out, name, p)
		if err != nil {
			s := fail("trivy (%s): %v", p, err)
			return &s
		}
		_, _ = fmt.Fprintf(o.Out, "trivy %s: %d vulnerabilities\n", p, len(fs))
		findings = append(findings, fs...)
	}
	r.Findings = findings
	d := policy.Evaluate(finding.Result{Findings: findings}, o.Config, false, time.Now())
	r.Blocking = d.Blocking
	if d.ExitCode() == 0 {
		return nil
	}
	for _, f := range d.Blocking {
		_, _ = fmt.Fprintf(o.Out, "%s  %s  %s\n", strings.ToUpper(f.Severity.String()), f.ID, f.File)
	}
	s := StepResult{Status: "blocked", Reason: fmt.Sprintf("%d image finding(s) above the policy threshold; %s", len(d.Blocking), untouched)}
	return &s
}

// tagAndSign tags the image at from with tags, signs signRef and records digest.
// It returns the failed step, or nil.
func tagAndSign(ctx context.Context, o Options, r *Result, crane, cosign, from string, tags []string, signRef, digest string) *StepResult {
	for _, t := range tags {
		if _, err := o.Exec.Run(ctx, o.Dir, nil, o.Out, crane, "tag", from, t); err != nil {
			s := fail("crane tag %s: %v", t, err)
			return &s
		}
	}
	if _, err := o.Exec.Run(ctx, o.Dir, nil, o.Out, cosign, "sign", "--yes", signRef); err != nil {
		s := fail("cosign sign: %v", err)
		return &s
	}
	r.ImageDigest = digest
	return nil
}
