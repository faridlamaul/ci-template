package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/faridlamaul/shipguard/internal/ci"
	"github.com/faridlamaul/shipguard/internal/ci/detect"
	"github.com/faridlamaul/shipguard/internal/ci/lang"
	cirun "github.com/faridlamaul/shipguard/internal/ci/run"
	"github.com/faridlamaul/shipguard/internal/ci/tools"
	"github.com/faridlamaul/shipguard/internal/exitcode"
	"github.com/faridlamaul/shipguard/internal/policy"
	"github.com/faridlamaul/shipguard/internal/report"
)

// ciLanguages returns the supported languages; tests replace it.
var ciLanguages = lang.All

// ciToolResolver returns the tool lookup used by language steps and the
// pinned defaults table; tests replace it so they never hit the network.
var ciToolResolver = func(dir string) (func(context.Context, string) (string, error), map[string]string, error) {
	specs, defaults, err := tools.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("load tools: %w", err)
	}
	cache := &tools.Cache{Dir: filepath.Join(dir, ".shipguard-cache", "tools"), Arch: runtime.GOARCH}
	return func(ctx context.Context, name string) (string, error) {
		t, ok := specs[name]
		if !ok {
			return "", fmt.Errorf("unknown tool %q", name)
		}
		return cache.Ensure(ctx, t)
	}, defaults, nil
}

// ciInputs holds the ci-local flag values.
type ciInputs struct {
	language  string
	toolchain string
	format    string
}

func ciCmd(g *globals, getenv func(string) string, stdout, stderr io.Writer) *cobra.Command {
	in := &ciInputs{}
	cmd := &cobra.Command{
		Use:   "ci [install|lint|test|build ...]",
		Short: "Run install, lint, test and build for the project",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doCI(cmd.Context(), g, in, args, getenv, stdout, stderr)
		},
	}
	pf := cmd.PersistentFlags()
	pf.StringVar(&in.language, "language", "", "project language (overrides ci.language)")
	pf.StringVar(&in.toolchain, "toolchain", "", "toolchain version (overrides ci.version)")

	detectCmd := &cobra.Command{
		Use:   "detect",
		Short: "Print the detected language and toolchain version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return doCIDetect(g, in, stdout)
		},
	}
	detectCmd.Flags().StringVar(&in.format, "format", "text", "output format: text or json")
	cmd.AddCommand(detectCmd)
	return cmd
}

// ciConfig loads the head config (never the base policy) and applies the
// --language and --toolchain overrides.
func ciConfig(g *globals, in *ciInputs) (policy.CIConfig, error) {
	path := g.config
	if path == "" {
		path = ".shipguard.yaml"
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(g.dir, path)
	}
	cfg, err := policy.Load(path)
	if err != nil {
		return policy.CIConfig{}, err
	}
	c := cfg.CI
	if in.language != "" {
		c.Language = in.language
	}
	if in.toolchain != "" {
		c.Version = in.toolchain
	}
	return c, nil
}

func doCIDetect(g *globals, in *ciInputs, stdout io.Writer) error {
	if in.format != "text" && in.format != "json" {
		return fail(fmt.Errorf("--format must be text or json, got %q", in.format))
	}
	cfg, err := ciConfig(g, in)
	if err != nil {
		return fail(err)
	}
	_, defaults, err := ciToolResolver(g.dir)
	if err != nil {
		return fail(err)
	}
	_, det, err := detect.Detect(g.dir, cfg, ciLanguages(), defaults)
	if err != nil {
		return fail(err)
	}
	if in.format == "json" {
		b, err := json.Marshal(struct {
			Language string `json:"language"`
			Version  string `json:"version"`
			Source   string `json:"source"`
		}{det.Language, det.Version, det.Source})
		if err != nil {
			return fail(err)
		}
		_, err = fmt.Fprintf(stdout, "%s\n", b)
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s %s (%s)\n", det.Language, det.Version, det.Source)
	return err
}

var ciStepOrder = []ci.StepName{"install", "lint", "test", "build"}

// selectSteps returns the step names to run: install is always implied.
func selectSteps(args []string) ([]ci.StepName, error) {
	if len(args) == 0 {
		return ciStepOrder, nil
	}
	want := map[ci.StepName]bool{"install": true}
	for _, a := range args {
		n := ci.StepName(a)
		if !slices.Contains(ciStepOrder, n) {
			return nil, fmt.Errorf("unknown step %q (want install, lint, test or build)", a)
		}
		want[n] = true
	}
	var out []ci.StepName
	for _, n := range ciStepOrder {
		if want[n] {
			out = append(out, n)
		}
	}
	return out, nil
}

func doCI(ctx context.Context, g *globals, in *ciInputs, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	names, err := selectSteps(args)
	if err != nil {
		return fail(err)
	}
	cfg, err := ciConfig(g, in)
	if err != nil {
		return fail(err)
	}
	toolFn, defaults, err := ciToolResolver(g.dir)
	if err != nil {
		return fail(err)
	}
	l, det, err := detect.Detect(g.dir, cfg, ciLanguages(), defaults)
	if err != nil {
		return fail(err)
	}
	installed, err := l.Toolchain(ctx, func(ctx context.Context, argv ...string) (string, error) {
		c := exec.CommandContext(ctx, argv[0], argv[1:]...)
		c.Dir = g.dir
		b, err := c.Output()
		return strings.TrimSpace(string(b)), err
	})
	if err != nil {
		return fail(fmt.Errorf("toolchain %s not found: %w", l.Name(), err))
	}
	var warning string
	if versionMismatch(det.Version, installed) {
		warning = fmt.Sprintf("%s %s requested but %s is installed", det.Language, det.Version, installed)
		fmt.Fprintf(stderr, "warning: %s\n", warning)
	}
	all, err := l.Steps(ctx, ci.Env{Dir: g.dir, Tools: toolFn, Defaults: defaults}, det, cfg)
	if err != nil {
		return fail(err)
	}
	var steps []ci.Step
	for _, s := range all {
		if slices.Contains(names, s.Name) {
			steps = append(steps, s)
		}
	}
	rs := cirun.Run(ctx, g.dir, steps, stdout)
	if warning != "" {
		for i := range rs {
			if rs[i].Name == "install" {
				rs[i].Warnings = append(rs[i].Warnings, warning)
			}
		}
	}
	res := report.CIResult{Language: det.Language, Version: det.Version, Source: det.Source, Steps: rs, Dir: g.dir}
	if err := report.WriteCI(g.dir, res, getenv); err != nil {
		fmt.Fprintf(stderr, "warning: write ci results: %s\n", err)
	}
	if getenv("GITHUB_ACTIONS") == "true" {
		var failures []report.TestFailure
		if f, err := os.Open(filepath.Join(g.dir, ".shipguard", "ci", "test-results", "junit.xml")); err == nil {
			failures, err = report.MergeJUnit([]string{f.Name()}, io.Discard)
			if err != nil {
				fmt.Fprintf(stderr, "warning: read junit: %s\n", err)
			}
			_ = f.Close()
		} else if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "warning: read junit: %s\n", err)
		}
		if err := report.CIGitHub(res, failures, getenv, stdout); err != nil {
			fmt.Fprintf(stderr, "warning: github annotations: %s\n", err)
		}
	}
	code := cirun.ExitCode(rs, cirun.Interrupted(rs) || ctx.Err() != nil)
	if code != exitcode.Pass {
		return &exitcode.Err{Code: code, Err: errReported}
	}
	return nil
}

var numRe = regexp.MustCompile(`\d+`)

// versionMismatch compares major.minor of the detected and installed
// versions. Ranges and channels (detected not starting with a digit) are
// never a mismatch.
func versionMismatch(detected, installed string) bool {
	if detected == "" || detected[0] < '0' || detected[0] > '9' {
		return false
	}
	d := numRe.FindAllString(detected, 2)
	i := numRe.FindAllString(installed, 2)
	if len(i) == 0 {
		return false
	}
	for k := range d {
		if k >= len(i) {
			return false
		}
		a, _ := strconv.Atoi(d[k])
		b, _ := strconv.Atoi(i[k])
		if a != b {
			return true
		}
	}
	return false
}
