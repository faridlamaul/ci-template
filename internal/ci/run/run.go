// Package run executes ci.Steps with timeouts and process-group cleanup.
package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/faridlamaul/shipguard/internal/ci"
)

// waitDelay bounds how long Wait lingers on output pipes after a kill.
const waitDelay = 2 * time.Second

// StepResult is the outcome of one step.
type StepResult struct {
	Name     ci.StepName   `json:"name"`
	Status   string        `json:"status"`           // passed | failed | skipped
	Reason   string        `json:"reason,omitempty"` // skip reason, "timeout", "cancelled", or "exit N"
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration_ns"`
	JUnit    []string      `json:"junit,omitempty"` // files actually found
	Coverage string        `json:"coverage,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

// Run executes steps in order, streaming raw output to out. Every step runs
// even when an earlier one fails, except after a failed install (P6).
func Run(ctx context.Context, dir string, steps []ci.Step, out io.Writer) []StepResult {
	rs := make([]StepResult, 0, len(steps))
	installFailed := false
	for _, s := range steps {
		reason := s.Skip
		if reason == "" && installFailed {
			reason = "install failed"
		}
		if reason != "" {
			_, _ = fmt.Fprintf(out, "==> %s (skipped: %s)\n", s.Name, reason)
			rs = append(rs, StepResult{Name: s.Name, Status: "skipped", Reason: reason})
			continue
		}
		_, _ = fmt.Fprintf(out, "==> %s\n", s.Name)
		r := runStep(ctx, dir, s, out)
		if s.Name == "install" && r.Status == "failed" {
			installFailed = true
		}
		rs = append(rs, r)
	}
	return rs
}

func runStep(ctx context.Context, dir string, s ci.Step, out io.Writer) StepResult {
	start := time.Now()
	r := StepResult{Name: s.Name, Status: "passed"}
	sctx := ctx
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		sctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	fail := func(reason string, code int) {
		r.Status, r.Reason, r.ExitCode = "failed", reason, code
	}
	// interrupt classifies a done step context as cancelled or timeout.
	interrupt := func(code int) bool {
		if sctx.Err() == nil {
			return false
		}
		if ctx.Err() != nil {
			fail("cancelled", code)
		} else {
			fail("timeout", code)
		}
		return true
	}
	if len(s.Cmds) == 0 {
		fail("no commands", 0) // producer bug: a step that ran nothing is never a pass
	}
	for _, c := range s.Cmds {
		code, err := runCmd(sctx, dir, c, out)
		if interrupt(code) {
			break
		}
		if err != nil {
			_, _ = fmt.Fprintf(out, "shipguard: %v\n", err)
			if code == 0 {
				code = -1
			}
		}
		if code != 0 {
			fail(fmt.Sprintf("exit %d", code), code)
			break
		}
	}
	if r.Status == "passed" && s.After != nil {
		if err := s.After(sctx, dir); err != nil {
			if !interrupt(0) {
				fail("after: "+err.Error(), 0)
			}
		}
	}
	if r.Status == "passed" {
		interrupt(0)
	}

	for _, g := range s.JUnit {
		found, _ := doublestar.Glob(os.DirFS(dir), filepath.ToSlash(g))
		if len(found) == 0 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("no JUnit found for %s (%s)", s.Name, g))
			continue
		}
		r.JUnit = append(r.JUnit, found...)
	}
	sort.Strings(r.JUnit)
	if s.Coverage != "" {
		if _, err := os.Stat(filepath.Join(dir, s.Coverage)); err == nil {
			r.Coverage = s.Coverage
		} else {
			r.Warnings = append(r.Warnings, fmt.Sprintf("no coverage found for %s (%s)", s.Name, s.Coverage))
		}
	}
	r.Duration = time.Since(start)
	return r
}

// runCmd runs one command and returns its exit code. A start failure or
// signal death yields (0, err) / (-1, nil) respectively.
func runCmd(ctx context.Context, dir string, c ci.Cmd, out io.Writer) (int, error) {
	var cmd *exec.Cmd
	switch {
	case c.Shell != "":
		cmd = exec.CommandContext(ctx, "sh", "-c", c.Shell)
	case len(c.Argv) > 0:
		cmd = exec.CommandContext(ctx, c.Argv[0], c.Argv[1:]...)
	default:
		return 0, errors.New("empty command")
	}
	cmd.Dir = dir
	cmd.Env = os.Environ()
	for k, v := range c.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdout, cmd.Stderr = out, out
	setGroup(cmd)
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = waitDelay

	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil // -1 when killed by a signal
	}
	return 0, err
}

// Interrupted reports whether any step timed out or was cancelled.
func Interrupted(rs []StepResult) bool {
	for _, r := range rs {
		if r.Status == "failed" && (r.Reason == "timeout" || r.Reason == "cancelled") {
			return true
		}
	}
	return false
}

// ExitCode implements P7: interrupted => 2; any failed => 1; no passed => 2;
// else 0. A passing install does not count as a pass when other steps were
// requested: a run where every requested step was skipped is exit 2. It
// counts only when install is the sole step (`shipguard ci install`).
func ExitCode(rs []StepResult, interrupted bool) int {
	if interrupted {
		return 2
	}
	passed := false
	for _, r := range rs {
		switch r.Status {
		case "failed":
			return 1
		case "passed":
			if r.Name != "install" || len(rs) == 1 {
				passed = true
			}
		}
	}
	if !passed {
		return 2
	}
	return 0
}
