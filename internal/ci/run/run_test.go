//go:build unix

package run

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/faridlamaul/shipguard/internal/ci"
)

func sh(s string) []ci.Cmd { return []ci.Cmd{{Shell: s}} }

func TestRunPassFailSkip(t *testing.T) {
	steps := []ci.Step{
		{Name: "lint", Cmds: sh("exit 0")},
		{Name: "test", Cmds: sh("exit 3")},
		{Name: "build", Skip: "disabled in config"},
	}
	rs := Run(context.Background(), t.TempDir(), steps, &bytes.Buffer{})
	if len(rs) != 3 {
		t.Fatalf("got %d results", len(rs))
	}
	if rs[0].Name != "lint" || rs[0].Status != "passed" {
		t.Errorf("lint: %+v", rs[0])
	}
	if rs[1].Status != "failed" || rs[1].ExitCode != 3 || rs[1].Reason != "exit 3" {
		t.Errorf("test: %+v", rs[1])
	}
	if rs[2].Status != "skipped" || rs[2].Reason != "disabled in config" {
		t.Errorf("build: %+v", rs[2])
	}
}

func TestRunContinuesAfterFailure(t *testing.T) {
	steps := []ci.Step{
		{Name: "lint", Cmds: sh("exit 1")},
		{Name: "test", Cmds: sh("exit 0")},
	}
	rs := Run(context.Background(), t.TempDir(), steps, &bytes.Buffer{})
	if rs[0].Status != "failed" || rs[1].Status != "passed" {
		t.Errorf("%+v", rs)
	}
}

func TestRunCmdsStopAtFirstFailure(t *testing.T) {
	dir := t.TempDir()
	steps := []ci.Step{{Name: "test", Cmds: []ci.Cmd{{Shell: "exit 2"}, {Shell: "touch ran"}}}}
	rs := Run(context.Background(), dir, steps, &bytes.Buffer{})
	if rs[0].Status != "failed" || rs[0].ExitCode != 2 {
		t.Errorf("%+v", rs[0])
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err == nil {
		t.Error("second cmd ran")
	}
}

func TestRunInstallFailureSkipsRest(t *testing.T) {
	steps := []ci.Step{
		{Name: "install", Cmds: sh("exit 1")},
		{Name: "lint", Cmds: sh("exit 0")},
		{Name: "test", Cmds: sh("exit 0")},
	}
	rs := Run(context.Background(), t.TempDir(), steps, &bytes.Buffer{})
	if rs[0].Status != "failed" {
		t.Errorf("%+v", rs[0])
	}
	for _, r := range rs[1:] {
		if r.Status != "skipped" || r.Reason != "install failed" {
			t.Errorf("%+v", r)
		}
	}
}

func pidGone(pid int) bool {
	for i := 0; i < 50; i++ {
		if err := syscall.Kill(pid, 0); err != nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestRunTimeoutKillsProcessGroup(t *testing.T) {
	dir := t.TempDir()
	steps := []ci.Step{{
		Name:    "test",
		Cmds:    sh("sleep 300 & echo $! > pid; sleep 300"),
		Timeout: 1500 * time.Millisecond,
	}}
	start := time.Now()
	rs := Run(context.Background(), dir, steps, &bytes.Buffer{})
	if time.Since(start) > 10*time.Second {
		t.Fatal("too slow")
	}
	if rs[0].Status != "failed" || rs[0].Reason != "timeout" {
		t.Fatalf("%+v", rs[0])
	}
	b, err := os.ReadFile(filepath.Join(dir, "pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	if !pidGone(pid) {
		t.Errorf("background sleep %d still alive", pid)
	}
	if got := ExitCode(rs, Interrupted(rs)); got != 2 {
		t.Errorf("exit = %d", got)
	}
}

func TestRunNoCommandsFails(t *testing.T) {
	rs := Run(context.Background(), t.TempDir(), []ci.Step{{Name: "test"}}, &bytes.Buffer{})
	if rs[0].Status != "failed" || rs[0].Reason != "no commands" {
		t.Errorf("%+v", rs[0])
	}
	if got := ExitCode(rs, false); got != 1 {
		t.Errorf("exit = %d", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rs = Run(ctx, t.TempDir(), []ci.Step{{Name: "test", Cmds: sh("true")}}, &bytes.Buffer{})
	if rs[0].Status != "failed" || rs[0].Reason != "cancelled" {
		t.Errorf("pre-cancelled: %+v", rs[0])
	}
}

func TestRunAfterTimeout(t *testing.T) {
	steps := []ci.Step{{
		Name: "test", Cmds: sh("true"), Timeout: 200 * time.Millisecond,
		After: func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() },
	}}
	rs := Run(context.Background(), t.TempDir(), steps, &bytes.Buffer{})
	if rs[0].Status != "failed" || rs[0].Reason != "timeout" {
		t.Fatalf("%+v", rs[0])
	}
	if got := ExitCode(rs, Interrupted(rs)); got != 2 {
		t.Errorf("exit = %d", got)
	}
}

func TestRunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	steps := []ci.Step{{Name: "test", Cmds: sh("sleep 300")}}
	rs := Run(ctx, t.TempDir(), steps, &bytes.Buffer{})
	if rs[0].Status != "failed" || rs[0].Reason != "cancelled" {
		t.Fatalf("%+v", rs[0])
	}
	if got := ExitCode(rs, Interrupted(rs)); got != 2 {
		t.Errorf("exit = %d", got)
	}
}

func TestRunStreamsOutput(t *testing.T) {
	var out bytes.Buffer
	steps := []ci.Step{
		{Name: "lint", Cmds: sh("echo hello; echo oops >&2")},
		{Name: "build", Skip: "nope"},
	}
	Run(context.Background(), t.TempDir(), steps, &out)
	s := out.String()
	for _, want := range []string{"==> lint\n", "hello\n", "oops\n", "==> build (skipped: nope)\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in %q", want, s)
		}
	}
}

func TestRunJUnitCoverageAfterEnv(t *testing.T) {
	dir := t.TempDir()
	var afterRan bool
	steps := []ci.Step{
		{
			Name:     "test",
			Cmds:     []ci.Cmd{{Shell: `mkdir -p r/a && echo x > r/a/one.xml && echo "$FOO" > cov.xml`, Env: map[string]string{"FOO": "bar"}}},
			JUnit:    []string{"r/**/*.xml", "missing/*.xml"},
			Coverage: "cov.xml",
			After:    func(context.Context, string) error { afterRan = true; return nil },
		},
		{Name: "build", Cmds: sh("true"), Coverage: "nocov.xml"},
		{Name: "lint", Cmds: sh("true"), After: func(context.Context, string) error { return os.ErrInvalid }},
	}
	rs := Run(context.Background(), dir, steps, &bytes.Buffer{})
	r := rs[0]
	if len(r.JUnit) != 1 || r.JUnit[0] != "r/a/one.xml" || r.Coverage != "cov.xml" || !afterRan {
		t.Errorf("%+v", r)
	}
	if len(r.Warnings) != 1 || r.Warnings[0] != "no JUnit found for test (missing/*.xml)" {
		t.Errorf("warnings %v", r.Warnings)
	}
	if rs[1].Coverage != "" || len(rs[1].Warnings) != 1 || rs[1].Warnings[0] != "no coverage found for build (nocov.xml)" {
		t.Errorf("%+v", rs[1])
	}
	if rs[2].Status != "failed" || rs[2].Reason != "after: invalid argument" || rs[2].ExitCode != 0 {
		t.Errorf("%+v", rs[2])
	}
}

func TestExitCode(t *testing.T) {
	p := StepResult{Name: "test", Status: "passed"}
	f := StepResult{Name: "test", Status: "failed"}
	s := StepResult{Name: "lint", Status: "skipped"}
	ip := StepResult{Name: "install", Status: "passed"}
	inf := StepResult{Name: "install", Status: "failed"}
	is := StepResult{Name: "test", Status: "skipped", Reason: "install failed"}
	tests := []struct {
		name string
		rs   []StepResult
		intr bool
		want int
	}{
		{"all pass", []StepResult{p, p}, false, 0},
		{"pass+skip", []StepResult{p, s}, false, 0},
		{"fail", []StepResult{p, f}, false, 1},
		{"all skipped", []StepResult{s, s}, false, 2},
		{"empty", nil, false, 2},
		{"interrupted", []StepResult{p, f}, true, 2},
		{"interrupted pass", []StepResult{p}, true, 2},
		{"install+pass", []StepResult{ip, p, s}, false, 0},
		{"only install passed", []StepResult{ip, s, s}, false, 2},
		{"install alone requested", []StepResult{ip}, false, 0},
		{"install failed", []StepResult{inf, is, is}, false, 1},
	}
	for _, tc := range tests {
		if got := ExitCode(tc.rs, tc.intr); got != tc.want {
			t.Errorf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}
