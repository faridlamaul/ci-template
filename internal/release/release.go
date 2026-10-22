// Package release orchestrates `shipguard release`: version, binaries, image.
package release

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/policy"
)

// Exec runs external commands.
type Exec interface {
	// Run runs name with args in dir; env entries are appended to os.Environ().
	// Output streams to out; the returned bytes are stdout.
	Run(ctx context.Context, dir string, env []string, out io.Writer, name string, args ...string) ([]byte, error)
}

// OSExec runs commands with os/exec, without a shell.
type OSExec struct{}

// Run implements Exec.
func (OSExec) Run(ctx context.Context, dir string, env []string, out io.Writer, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stdout bytes.Buffer
	cmd.Stdout = io.MultiWriter(&stdout, out)
	cmd.Stderr = out
	err := cmd.Run()
	return stdout.Bytes(), err
}

// Options configures Run.
type Options struct {
	Dir        string
	CacheDir   string // pinned-tool and trivy cache root, outside the repository
	Config     policy.Config
	Steps      []string // subset of "version","binaries","image"; empty = all
	DryRun     bool
	Prerelease string
	Tool       func(ctx context.Context, name string) (string, error) // path of a pinned tool
	Exec       Exec
	Getenv     func(string) string
	Out        io.Writer
	Sleep      func(time.Duration) // waits between image push attempts; nil = time.Sleep
}

// StepResult is the outcome of one step.
type StepResult struct {
	Name     string
	Status   string // passed | failed | blocked | skipped | not run
	Reason   string
	Duration time.Duration
}

// Result is the outcome of a release run.
type Result struct {
	Released    bool
	Tag         string // "v1.4.0"
	Version     string // "1.4.0"
	Image       string
	ImageDigest string
	Steps       []StepResult
	Findings    []finding.Finding // image findings; never fed to SARIF reporters
	Blocking    []finding.Finding // the findings that block the image gate

	usageErr error // config problem found inside a step; Run returns it (exit 2)
}

const dryRunVersion = "0.0.0-dryrun"

var stepNames = []string{"version", "binaries", "image"}

// Run executes the selected steps in order. The error is only for usage or
// config problems (exit 2); step failures are reported in the Result.
func Run(ctx context.Context, o Options) (Result, error) {
	sel := map[string]bool{}
	for _, s := range o.Steps {
		ok := false
		for _, n := range stepNames {
			ok = ok || n == s
		}
		if !ok {
			return Result{}, fmt.Errorf("unknown release step %q (want version, binaries or image)", s)
		}
		sel[s] = true
	}
	if o.Tool == nil || o.Exec == nil {
		return Result{}, fmt.Errorf("release: Tool and Exec are required")
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.CacheDir == "" {
		d, err := CacheRoot(o.Getenv)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %v", policy.ErrConfig, err)
		}
		o.CacheDir = d
	}
	want := func(n string) bool { return len(sel) == 0 || sel[n] }

	var r Result
	failed := false
	run := func(name string, f func() StepResult) {
		if !want(name) {
			r.Steps = append(r.Steps, StepResult{Name: name, Status: "skipped", Reason: "not selected"})
			return
		}
		if failed {
			r.Steps = append(r.Steps, StepResult{Name: name, Status: "not run"})
			return
		}
		_, _ = fmt.Fprintf(o.Out, "==> %s\n", name)
		start := time.Now()
		s := f()
		s.Name, s.Duration = name, time.Since(start)
		failed = s.Status == "failed" || s.Status == "blocked"
		r.Steps = append(r.Steps, s)
	}
	skipNothing := func() (StepResult, bool) {
		if r.Version == "" {
			if !want("version") {
				return StepResult{Status: "skipped", Reason: "no release tag at HEAD (version step not selected)"}, true
			}
			return StepResult{Status: "skipped", Reason: "nothing to release"}, true
		}
		return StepResult{}, false
	}

	if want("version") {
		run("version", func() StepResult { return version(ctx, o, &r) })
	} else {
		r.Steps = append(r.Steps, StepResult{Name: "version", Status: "skipped", Reason: "not selected"})
		resolveHeadTag(ctx, o, &r)
	}
	run("binaries", func() StepResult {
		if s, ok := skipNothing(); ok {
			return s
		}
		return binaries(ctx, o, &r)
	})
	run("image", func() StepResult {
		if s, ok := skipNothing(); ok {
			return s
		}
		return imageStep(ctx, o, &r)
	})
	if o.DryRun {
		r.Released = false // downstream jobs key on released; a dry run never releases
	}
	return r, r.usageErr
}

// ExitCode is 1 when any step failed or was blocked, else 0.
func (r Result) ExitCode() int {
	for _, s := range r.Steps {
		if s.Status == "failed" || s.Status == "blocked" {
			return 1
		}
	}
	return 0
}

// imageStep is a seam so tests can prove the image step was invoked.
var imageStep = image

// CacheRoot is where the release command keeps its pinned tools and the trivy
// cache: outside the repository, so they never reach the docker build context
// or the working-tree status. It is $RUNNER_TEMP/shipguard-cache on a CI
// runner, else the user cache directory.
func CacheRoot(getenv func(string) string) (string, error) {
	if t := getenv("RUNNER_TEMP"); t != "" {
		return filepath.Join(t, "shipguard-cache"), nil
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("release cache directory: %w", err)
	}
	return filepath.Join(d, "shipguard"), nil
}
