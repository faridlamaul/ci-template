package release

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/policy"
)

const fakeLayoutDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// imgExec fakes docker, trivy, crane and cosign.
type imgExec struct {
	calls       []call
	buildxErr   error
	trivyOut    []byte
	trivyErr    error
	craneDigest string // "" = crane digest fails with digestErr
	digestErr   string // text of the crane digest failure; default MANIFEST_UNKNOWN
	layouts     []string
	pushOut     string
}

func (f *imgExec) Run(_ context.Context, _ string, env []string, _ io.Writer, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, args, env})
	switch filepath.Base(name) {
	case "docker":
		if args[0] == "buildx" && args[1] == "version" {
			return nil, f.buildxErr
		}
		for i, a := range args {
			if a == "--output" {
				dest := strings.TrimSuffix(strings.TrimPrefix(args[i+1], "type=oci,dest="), ",tar=false")
				f.layouts = append(f.layouts, dest)
				_ = os.MkdirAll(dest, 0o700)
				idx := `{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"` + fakeLayoutDigest + `","size":1}]}`
				_ = os.WriteFile(filepath.Join(dest, "index.json"), []byte(idx), 0o600)
			}
		}
	case "trivy":
		return f.trivyOut, f.trivyErr
	case "crane":
		switch args[0] {
		case "digest":
			if f.craneDigest == "" {
				msg := f.digestErr
				if msg == "" {
					msg = "GET https://ghcr.io/v2/o/app/manifests/v1.4.0: MANIFEST_UNKNOWN: manifest unknown"
				}
				return nil, errors.New(msg)
			}
			return []byte(f.craneDigest + "\n"), nil
		case "push":
			return []byte(f.pushOut), nil
		}
	}
	return nil, nil
}

func (f *imgExec) names() []string {
	var n []string
	for _, c := range f.calls {
		s := filepath.Base(c.name)
		if len(c.args) > 0 {
			s += " " + c.args[0]
		}
		n = append(n, s)
	}
	return n
}

func (f *imgExec) all(base string) []call {
	var out []call
	for _, c := range f.calls {
		if filepath.Base(c.name) == base {
			out = append(out, c)
		}
	}
	return out
}

func imgOpts(t *testing.T, f *imgExec) Options {
	t.Helper()
	o := opts(t, nil)
	o.Exec = f
	o.Config.Release.Image.Name = "ghcr.io/o/app"
	if err := os.WriteFile(filepath.Join(o.Dir, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return o
}

func cleanTrivy() []byte { return []byte(`{"Results":[]}`) }

func runImage(t *testing.T, o Options, version string) (Result, StepResult, error) {
	t.Helper()
	r := Result{Released: true, Tag: "v" + version, Version: version}
	s := image(context.Background(), o, &r)
	return r, s, r.usageErr
}

func TestImageTags(t *testing.T) {
	if got := strings.Join(imageTags("1.4.0"), " "); got != "v1.4.0 1.4.0 v1.4 v1" {
		t.Fatalf("got %q", got)
	}
	if got := strings.Join(imageTags("1.4.0-rc.1"), " "); got != "v1.4.0-rc.1 1.4.0-rc.1" {
		t.Fatalf("got %q", got)
	}
}

func TestImageSkippedNoDockerfile(t *testing.T) {
	f := &imgExec{}
	o := imgOpts(t, f)
	_ = os.Remove(filepath.Join(o.Dir, "Dockerfile"))
	_, s, _ := runImage(t, o, "1.4.0")
	if s.Status != "skipped" || len(f.calls) != 0 {
		t.Fatalf("s=%+v calls=%v", s, f.names())
	}
}

func TestImageDefaultName(t *testing.T) {
	f := &imgExec{trivyOut: cleanTrivy(), pushOut: "x@" + fakeLayoutDigest}
	o := imgOpts(t, f)
	o.Config.Release.Image.Name = ""
	o.Getenv = func(k string) string {
		if k == "GITHUB_REPOSITORY" {
			return "FaridLamaul/My-App"
		}
		return ""
	}
	r, s, err := runImage(t, o, "1.4.0")
	if err != nil || s.Status != "passed" || r.Image != "ghcr.io/faridlamaul/my-app" {
		t.Fatalf("err=%v s=%+v image=%q", err, s, r.Image)
	}

	f2 := &imgExec{}
	o2 := imgOpts(t, f2)
	o2.Config.Release.Image.Name = ""
	o2.Getenv = func(string) string { return "" }
	_, s2, err2 := runImage(t, o2, "1.4.0")
	if err2 == nil || s2.Status != "failed" || len(f2.calls) != 0 {
		t.Fatalf("err=%v s=%+v", err2, s2)
	}
}

func TestImageBuildArgs(t *testing.T) {
	f := &imgExec{trivyOut: cleanTrivy(), pushOut: "x@" + fakeLayoutDigest}
	o := imgOpts(t, f)
	o.Config.Release.Image.BuildArgs = map[string]string{"B": "2", "A": "1"}
	if _, s, err := runImage(t, o, "1.4.0"); err != nil || s.Status != "passed" {
		t.Fatalf("err=%v s=%+v", err, s)
	}
	var c call
	for _, x := range f.all("docker") {
		if x.args[0] == "buildx" && x.args[1] == "build" {
			c = x
		}
	}
	a := strings.Join(c.args, " ")
	for _, w := range []string{
		"buildx build", "--platform linux/amd64,linux/arm64", "--provenance=mode=max", "--sbom=true",
		"--build-arg VERSION=1.4.0 --build-arg A=1 --build-arg B=2", ",tar=false", "-f Dockerfile",
	} {
		if !strings.Contains(a, w) {
			t.Errorf("missing %q in %q", w, a)
		}
	}
	if !strings.Contains(a, "--output type=oci,dest=") {
		t.Errorf("argv = %q", a)
	}
	if c.args[len(c.args)-1] != "." {
		t.Errorf("context must be last: %q", a)
	}
}

func TestImageVersionBuildArgForbidden(t *testing.T) {
	f := &imgExec{}
	o := imgOpts(t, f)
	o.Config.Release.Image.BuildArgs = map[string]string{"VERSION": "9"}
	_, s, err := runImage(t, o, "1.4.0")
	if err == nil || s.Status != "failed" || len(f.calls) != 0 {
		t.Fatalf("err=%v s=%+v", err, s)
	}
}

func TestImageNoBuildx(t *testing.T) {
	f := &imgExec{buildxErr: errors.New("no")}
	_, s, _ := runImage(t, imgOpts(t, f), "1.4.0")
	if s.Status != "failed" || !strings.Contains(s.Reason, "docker/setup-buildx-action") {
		t.Fatalf("s=%+v", s)
	}
}

func TestImageBlocked(t *testing.T) {
	raw, err := os.ReadFile("../scanner/testdata/trivy-image.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &imgExec{trivyOut: raw}
	o := imgOpts(t, f)
	o.Config.Policy.FailOn[finding.CategorySCA] = policy.Threshold{Severity: finding.High}
	r := Result{Released: true, Tag: "v1.4.0", Version: "1.4.0"}
	s := image(context.Background(), o, &r)
	r.Steps = []StepResult{s}
	if s.Status != "blocked" || r.ExitCode() != 1 || len(r.Findings) == 0 {
		t.Fatalf("s=%+v findings=%d", s, len(r.Findings))
	}
	if len(f.all("crane")) != 0 || len(f.all("cosign")) != 0 {
		t.Fatalf("calls = %v", f.names())
	}
	if _, err := os.Stat(filepath.Join(o.Dir, ".shipguard", "image-findings.json")); err == nil {
		t.Fatal("image findings must only be in Result.Findings")
	}
}

func TestImagePushSignOrder(t *testing.T) {
	f := &imgExec{trivyOut: cleanTrivy(), pushOut: "ghcr.io/o/app@" + fakeLayoutDigest + "\n"}
	o := imgOpts(t, f)
	r, s, err := runImage(t, o, "1.4.0")
	if err != nil || s.Status != "passed" || r.ImageDigest != fakeLayoutDigest || r.Image != "ghcr.io/o/app" {
		t.Fatalf("err=%v s=%+v r=%+v", err, s, r)
	}
	want := []string{
		"docker buildx", "docker buildx", "trivy image", "trivy image", "crane digest", "crane push",
		"crane tag", "crane tag", "crane tag", "cosign sign",
	}
	got := f.names()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v", got)
	}
	tr := f.all("trivy")
	cache := filepath.Join(o.Dir, ".shipguard-cache", "trivy")
	for i, p := range []string{"linux/amd64", "linux/arm64"} {
		a := strings.Join(tr[i].args, " ")
		if !strings.Contains(a, "--platform "+p+" --scanners vuln --format json --cache-dir "+cache) || !strings.Contains(a, "image --input ") {
			t.Errorf("trivy argv = %q", a)
		}
	}
	cr := f.all("crane")
	if strings.Join(cr[0].args, " ") != "digest ghcr.io/o/app:v1.4.0" {
		t.Errorf("digest = %v", cr[0].args)
	}
	if strings.Contains(strings.Join(cr[1].args, " "), "--index") || !strings.HasPrefix(strings.Join(cr[1].args, " "), "push ") || !strings.HasSuffix(strings.Join(cr[1].args, " "), " ghcr.io/o/app:v1.4.0") {
		t.Errorf("push = %v", cr[1].args)
	}
	for i, tag := range []string{"1.4.0", "v1.4", "v1"} {
		if strings.Join(cr[2+i].args, " ") != "tag ghcr.io/o/app:v1.4.0 "+tag {
			t.Errorf("tag %d = %v", i, cr[2+i].args)
		}
	}
	if got := strings.Join(f.all("cosign")[0].args, " "); got != "sign --yes ghcr.io/o/app@"+fakeLayoutDigest {
		t.Errorf("cosign = %q", got)
	}
}

func TestImageRerunSameDigest(t *testing.T) {
	f := &imgExec{trivyOut: cleanTrivy(), craneDigest: fakeLayoutDigest}
	r, s, err := runImage(t, imgOpts(t, f), "1.4.0")
	if err != nil || s.Status != "passed" || r.ImageDigest != fakeLayoutDigest {
		t.Fatalf("err=%v s=%+v r=%+v", err, s, r)
	}
	for _, c := range f.all("crane") {
		if c.args[0] == "push" {
			t.Fatal("push must be skipped")
		}
	}
	if len(f.all("cosign")) != 1 {
		t.Fatalf("calls = %v", f.names())
	}
	n := 0
	for _, c := range f.all("crane") {
		if c.args[0] == "tag" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("tags = %d", n)
	}
}

func TestImageRerunDifferentDigest(t *testing.T) {
	f := &imgExec{trivyOut: cleanTrivy(), craneDigest: "sha256:2222"}
	_, s, _ := runImage(t, imgOpts(t, f), "1.4.0")
	if s.Status != "failed" || !strings.Contains(s.Reason, "already published") {
		t.Fatalf("s=%+v", s)
	}
	for _, c := range f.all("crane") {
		if c.args[0] != "digest" {
			t.Fatalf("unexpected crane %v", c.args)
		}
	}
	if len(f.all("cosign")) != 0 {
		t.Fatal("no sign")
	}
}

func TestImageDryRun(t *testing.T) {
	f := &imgExec{trivyOut: cleanTrivy()}
	o := imgOpts(t, f)
	o.DryRun = true
	_, s, err := runImage(t, o, dryRunVersion)
	if err != nil || s.Status != "passed" || s.Reason != "dry run" {
		t.Fatalf("err=%v s=%+v", err, s)
	}
	if len(f.all("crane")) != 0 || len(f.all("cosign")) != 0 || len(f.all("trivy")) != 2 {
		t.Fatalf("calls = %v", f.names())
	}
}

func TestImageDigestOtherErrorFails(t *testing.T) {
	for _, msg := range []string{"GET https://x: UNAUTHORIZED: authentication required", "dial tcp: i/o timeout"} {
		f := &imgExec{trivyOut: cleanTrivy(), digestErr: msg}
		_, s, _ := runImage(t, imgOpts(t, f), "1.4.0")
		if s.Status != "failed" || !strings.Contains(s.Reason, "cannot check existing tag") {
			t.Fatalf("%q: s=%+v", msg, s)
		}
		for _, c := range f.all("crane") {
			if c.args[0] != "digest" {
				t.Fatalf("unexpected crane %v", c.args)
			}
		}
	}
}

func TestImageDigestAbsentMarkers(t *testing.T) {
	for _, msg := range []string{"name_unknown: repository name not known", "unexpected status code 404 Not Found"} {
		f := &imgExec{trivyOut: cleanTrivy(), digestErr: msg, pushOut: "x@" + fakeLayoutDigest}
		_, s, _ := runImage(t, imgOpts(t, f), "1.4.0")
		if s.Status != "passed" {
			t.Fatalf("%q: s=%+v", msg, s)
		}
	}
}

func TestImagePushNoDigestFails(t *testing.T) {
	f := &imgExec{trivyOut: cleanTrivy(), pushOut: "pushed\n"}
	_, s, _ := runImage(t, imgOpts(t, f), "1.4.0")
	if s.Status != "failed" || len(f.all("cosign")) != 0 {
		t.Fatalf("s=%+v", s)
	}
}

func TestImageTempLayoutRemoved(t *testing.T) {
	for _, f := range []*imgExec{
		{trivyOut: cleanTrivy(), pushOut: "x@" + fakeLayoutDigest},
		{trivyOut: cleanTrivy(), pushOut: "nodigest"},
	} {
		runImage(t, imgOpts(t, f), "1.4.0")
		if len(f.layouts) != 1 {
			t.Fatalf("layouts = %v", f.layouts)
		}
		if _, err := os.Stat(filepath.Dir(f.layouts[0])); err == nil {
			t.Fatalf("temp dir %s still exists", filepath.Dir(f.layouts[0]))
		}
	}
}

func TestImageTrivyNotLogged(t *testing.T) {
	f := &imgExec{trivyOut: []byte(`{"Results":[],"secret":"SENTINEL"}`), pushOut: "x@" + fakeLayoutDigest}
	o := imgOpts(t, f)
	var buf strings.Builder
	o.Out = &buf
	runImage(t, o, "1.4.0")
	if strings.Contains(buf.String(), "SENTINEL") || !strings.Contains(buf.String(), "trivy linux/amd64: 0 vulnerabilities") {
		t.Fatalf("out = %q", buf.String())
	}
}

func TestImageDigestOtherErrorNo404Match(t *testing.T) {
	f := &imgExec{trivyOut: cleanTrivy(), pushOut: "x@" + fakeLayoutDigest,
		digestErr: "GET https://ghcr.io/v2/o/app/manifests/v1.404.0: UNAUTHORIZED: authentication required"}
	_, s, _ := runImage(t, imgOpts(t, f), "1.404.0")
	if s.Status != "failed" || !strings.Contains(s.Reason, "cannot check existing tag") || !strings.Contains(s.Reason, "UNAUTHORIZED") {
		t.Fatalf("s=%+v", s)
	}
	for _, c := range f.all("crane") {
		if c.args[0] == "push" {
			t.Fatal("must not push")
		}
	}
}

func TestImagePushedDigestMismatch(t *testing.T) {
	f := &imgExec{trivyOut: cleanTrivy(), pushOut: "x@sha256:abc"}
	_, s, _ := runImage(t, imgOpts(t, f), "1.4.0")
	if s.Status != "failed" || !strings.Contains(s.Reason, "pushed digest does not match the scanned layout") || len(f.all("cosign")) != 0 {
		t.Fatalf("s=%+v", s)
	}
}
