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

	if _, err := o.Exec.Run(ctx, o.Dir, nil, io.Discard, "docker", "buildx", "version"); err != nil {
		return fail("docker buildx is not available; add docker/setup-buildx-action before shipguard release")
	}
	trivy, err := o.Tool(ctx, "trivy")
	if err != nil {
		return fail("%v", err)
	}
	var crane, cosign string
	if !o.DryRun {
		if crane, err = o.Tool(ctx, "crane"); err != nil {
			return fail("%v", err)
		}
		if cosign, err = o.Tool(ctx, "cosign"); err != nil {
			return fail("%v", err)
		}
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

	cache := filepath.Join(o.Dir, ".shipguard-cache", "trivy")
	var findings []finding.Finding
	for _, p := range cfg.Platforms {
		out, err := o.Exec.Run(ctx, o.Dir, nil, io.Discard, trivy, "image", "--input", layout,
			"--platform", p, "--scanners", "vuln", "--format", "json", "--cache-dir", cache)
		if err != nil {
			return fail("trivy (%s): %v", p, err)
		}
		fs, err := scanner.ParseTrivyImage(out, name, p)
		if err != nil {
			return fail("trivy (%s): %v", p, err)
		}
		_, _ = fmt.Fprintf(o.Out, "trivy %s: %d vulnerabilities\n", p, len(fs))
		findings = append(findings, fs...)
	}
	r.Findings = findings
	d := policy.Evaluate(finding.Result{Findings: findings}, o.Config, false, time.Now())
	if d.ExitCode() != 0 {
		for _, f := range d.Blocking {
			_, _ = fmt.Fprintf(o.Out, "%s  %s  %s\n", strings.ToUpper(f.Severity.String()), f.ID, f.File)
		}
		return StepResult{Status: "blocked", Reason: fmt.Sprintf("%d image finding(s) above the policy threshold; nothing was pushed", len(d.Blocking))}
	}
	if o.DryRun {
		return StepResult{Status: "passed", Reason: "dry run"}
	}

	tags := imageTags(r.Version)
	ref := name + ":" + tags[0]
	var digestLog bytes.Buffer // crane prints the registry error on stderr
	pub, err := o.Exec.Run(ctx, o.Dir, nil, &digestLog, crane, "digest", ref)
	if err != nil && !tagAbsent(err.Error()+" "+digestLog.String()) {
		return fail("cannot check existing tag: %v: %s", err, oneLine(digestLog.String(), 300))
	}
	switch {
	case err != nil: // absent: push. A one-entry layout pushes that entry, so the digest is manifests[0].digest.
		out, err := o.Exec.Run(ctx, o.Dir, nil, o.Out, crane, "push", layout, ref)
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
	case strings.TrimSpace(string(pub)) != digest:
		return fail("%s is already published with a different digest (%s); a published tag is never moved", ref, strings.TrimSpace(string(pub)))
	}
	for _, t := range tags[1:] {
		if _, err := o.Exec.Run(ctx, o.Dir, nil, o.Out, crane, "tag", ref, t); err != nil {
			return fail("crane tag %s: %v", t, err)
		}
	}
	if _, err := o.Exec.Run(ctx, o.Dir, nil, o.Out, cosign, "sign", "--yes", name+"@"+digest); err != nil {
		return fail("cosign sign: %v", err)
	}
	r.ImageDigest = digest
	return StepResult{Status: "passed", Reason: name + "@" + digest}
}
