// Command shipguard runs DevSecOps security scanners (secrets, SAST, SCA, IaC)
// in GitHub, GitLab, and Bitbucket pipelines and enforces a policy gate.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/faridlamaul/shipguard/internal/exitcode"
	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/gitx"
	"github.com/faridlamaul/shipguard/internal/platform"
	"github.com/faridlamaul/shipguard/internal/policy"
	"github.com/faridlamaul/shipguard/internal/report"
	"github.com/faridlamaul/shipguard/internal/scan"
	"github.com/faridlamaul/shipguard/internal/scanner"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

// defaultRulesDir holds the opengrep builtin rules in the release image.
const defaultRulesDir = "/opt/shipguard/rules"

// buildScanners returns the real scanners; tests replace it.
var buildScanners = func(rulesDir string) []scanner.Scanner {
	run := scanner.ExecRunner()
	return []scanner.Scanner{
		scanner.NewGitleaks(run),
		scanner.NewOpengrep(run, rulesDir),
		scanner.NewOSV(run),
		scanner.NewTrivyConfig(run),
		scanner.NewTrivyLicense(run),
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// globals holds the persistent flag values shared by every subcommand.
type globals struct {
	dir      string
	config   string
	mode     string
	scanners string

	format       string
	codeInsights bool
}

// bareVars is the allowlist of flags that may be set from a bare (non
// SHIPGUARD_-prefixed) Bitbucket pipe variable.
var bareVars = map[string]bool{"scanners": true, "mode": true, "config": true, "code-insights": true}

// run executes the CLI with injected arguments, environment, and writers and
// returns the process exit code.
func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	root, _ := newRoot(getenv, stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(stderr, "error: %s\n", err)
		var ee *exitcode.Err
		if errors.As(err, &ee) {
			return ee.Code
		}
		return exitcode.Error
	}
	return exitcode.Pass
}

// newRoot builds the command tree. Flag values resolve in the order explicit
// flag, SHIPGUARD_* variable, bare Bitbucket pipe variable, default.
func newRoot(getenv func(string) string, stdout, stderr io.Writer) (*cobra.Command, *globals) {
	g := &globals{codeInsights: true}
	root := &cobra.Command{
		Use:           "shipguard",
		Short:         "Security scanning and policy gate for GitHub, GitLab, and Bitbucket",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			gitx.SetConfig(platform.BitbucketPipeGitConfig(getenv))
			return resolveFlags(cmd.Flags(), g, getenv)
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	pf := root.PersistentFlags()
	pf.StringVar(&g.dir, "dir", "", "repository directory (default: the CI workspace, else the current directory)")
	pf.StringVar(&g.config, "config", "", "config file (default: .shipguard.yaml in the repository root)")
	pf.StringVar(&g.mode, "mode", "", "gate mode: enforce or audit")
	pf.StringVar(&g.scanners, "scanners", "", "comma-separated scanners to run")

	root.AddCommand(
		scanCmd(g, getenv, stdout, stderr),
		gateCmd(g, getenv, stdout),
		reportCmd(g, getenv, stderr),
		runCmd(g, getenv, stdout, stderr),
		versionCmd(stdout),
	)
	return root, g
}

// resolveFlags fills flags the user did not set from the environment.
func resolveFlags(fs *pflag.FlagSet, g *globals, getenv func(string) string) error {
	bitbucket := getenv("BITBUCKET_BUILD_NUMBER") != ""
	var err error
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Changed || err != nil {
			return
		}
		name := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		val := getenv("SHIPGUARD_" + name)
		if val == "" && bitbucket && bareVars[f.Name] {
			val = getenv(name)
		}
		if val != "" {
			err = f.Value.Set(val)
		}
	})
	if err != nil {
		return err
	}
	if g.dir == "" {
		for _, k := range []string{"GITHUB_WORKSPACE", "CI_PROJECT_DIR", "BITBUCKET_CLONE_DIR"} {
			if v := getenv(k); v != "" {
				g.dir = v
				break
			}
		}
	}
	if g.dir == "" {
		wd, werr := os.Getwd()
		if werr != nil {
			return &exitcode.Err{Code: exitcode.Error, Err: fmt.Errorf("resolve working directory: %w", werr)}
		}
		g.dir = wd
	}
	// Scanners and git run with other working directories, and reported
	// paths are made relative to the root: use one absolute, symlink-free
	// path. A missing directory is reported by the command that uses it.
	abs, err := filepath.Abs(g.dir)
	if err != nil {
		return &exitcode.Err{Code: exitcode.Error, Err: fmt.Errorf("resolve --dir: %w", err)}
	}
	if real, rerr := filepath.EvalSymlinks(abs); rerr == nil {
		abs = real
	}
	g.dir = abs
	return nil
}

// scanCmd runs the scanners and writes .shipguard/. It exits 2 on config or
// base-resolution errors and 0 otherwise: scanner errors are recorded in
// findings.json and the gate turns them into a failure.
func scanCmd(g *globals, getenv func(string) string, stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Run the configured scanners",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return doScan(cmd.Context(), g, getenv, stdout, stderr)
		},
	}
}

func doScan(ctx context.Context, g *globals, getenv func(string) string, stdout, stderr io.Writer) error {
	// Before any validation: a failed scan must not leave a previous run's
	// results for gate or report to pick up.
	if err := scan.ResetOutputs(g.dir); err != nil {
		return &exitcode.Err{Code: exitcode.Error, Err: err}
	}
	cats, err := scan.ParseCategories(g.scanners)
	if err != nil {
		return &exitcode.Err{Code: exitcode.Error, Err: err}
	}
	rulesDir := getenv("SHIPGUARD_RULES_DIR")
	if rulesDir == "" {
		rulesDir = defaultRulesDir
	}
	res, _, err := scan.Run(ctx, scan.Options{
		Dir:        g.dir,
		ConfigPath: g.config,
		Categories: cats,
		Ctx:        platform.Detect(getenv),
		Scanners:   buildScanners(rulesDir),
		Now:        time.Now,
		Version:    version,
		Mode:       g.mode,
	})
	if err != nil {
		return &exitcode.Err{Code: exitcode.Error, Err: err}
	}
	for _, r := range res.Scanners {
		if r.Status == finding.RunStatusError {
			fmt.Fprintf(stderr, "warning: %s failed: %s\n", r.Name, r.Error)
		}
	}
	_, err = fmt.Fprintf(stdout, "shipguard scan: %d findings, results in %s\n",
		len(res.Findings), filepath.Join(g.dir, scan.OutDir, "findings.json"))
	return err
}

// now is the clock used by gate; tests replace it.
var now = time.Now

// stepSummaryLimit is the GitHub step summary size limit (1 MiB, rounded down).
const stepSummaryLimit = 1_000_000

// gateCmd applies the policy to .shipguard/findings.json, writes the summary
// and CI outputs, and exits with the decision's code. A missing findings file
// or an invalid config fails closed with exit 2.
func gateCmd(g *globals, getenv func(string) string, stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "gate",
		Short: "Apply the policy to the scan results",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return doGate(g, getenv, stdout)
		},
	}
}

func fail(err error) error { return &exitcode.Err{Code: exitcode.Error, Err: err} }

// loadDecision reads findings.json and the effective config and evaluates the
// policy. It fails closed (exit 2) on a missing or unreadable findings file,
// a run in which no scanner completed, and a missing or invalid config
// (including a PR without the base-ref policy.yaml).
func loadDecision(g *globals) (finding.Result, policy.Decision, error) {
	if g.mode != "" && g.mode != "enforce" && g.mode != "audit" {
		return finding.Result{}, policy.Decision{}, fail(fmt.Errorf("--mode must be enforce or audit, got %q", g.mode))
	}
	out := filepath.Join(g.dir, scan.OutDir)
	res, err := finding.ReadResult(filepath.Join(out, "findings.json"))
	if err != nil {
		return res, policy.Decision{}, fail(fmt.Errorf("%w (run `shipguard scan` first)", err))
	}
	var pc platform.Context
	if len(res.Context) > 0 {
		if err := json.Unmarshal(res.Context, &pc); err != nil {
			return res, policy.Decision{}, fail(fmt.Errorf("parse context in findings.json: %w", err))
		}
	}
	pr := pc.Event == platform.EventPR
	if !scannerRan(res) {
		return res, policy.Decision{}, fail(errors.New("no scanner ran: findings.json has no completed scanner run"))
	}
	cfg, err := gateConfig(g, out, pr)
	if err != nil {
		return res, policy.Decision{}, fail(err)
	}
	if g.mode != "" {
		cfg.Mode = g.mode
	}
	return res, policy.Evaluate(res, cfg, pr, now()), nil
}

// doGate applies the policy, writes the summary and CI outputs, and returns an
// exit-coded error for a failing decision.
func doGate(g *globals, getenv func(string) string, stdout io.Writer) error {
	res, d, err := loadDecision(g)
	if err != nil {
		return err
	}
	out := filepath.Join(g.dir, scan.OutDir)
	if err := report.WriteOutputs(g.dir, d, getenv); err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(out, "summary.md"), []byte(report.Summary(res, d, 0)), 0o644); err != nil {
		return fail(fmt.Errorf("write summary: %w", err))
	}
	if p := getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if err := report.AppendStepSummary(p, report.Summary(res, d, stepSummaryLimit)); err != nil {
			return fail(err)
		}
	}
	if _, err := fmt.Fprint(stdout, report.Summary(res, d, 0)); err != nil {
		return fail(err)
	}
	if code := d.ExitCode(); code != exitcode.Pass {
		return &exitcode.Err{Code: code, Err: fmt.Errorf("gate %s: %d blocking findings, %d scanner errors",
			d.Result, len(d.Blocking), len(d.ScannerErrors))}
	}
	return nil
}

// scannerRan reports whether any scanner completed or failed; an empty or
// skipped-only list means nothing was scanned, which is never a pass.
func scannerRan(r finding.Result) bool {
	for _, s := range r.Scanners {
		if s.Status == finding.RunStatusOK || s.Status == finding.RunStatusError {
			return true
		}
	}
	return false
}

// gateConfig reads the effective config written by scan, falling back to the
// repository config when scan did not write one.
func gateConfig(g *globals, out string, pr bool) (policy.Config, error) {
	data, err := os.ReadFile(filepath.Join(out, "policy.yaml"))
	switch {
	case err == nil:
		cfg, perr := policy.Parse(data)
		if perr != nil {
			return policy.Config{}, fmt.Errorf("policy.yaml: %w", perr)
		}
		return cfg, nil
	case !errors.Is(err, os.ErrNotExist):
		return policy.Config{}, fmt.Errorf("read policy.yaml: %w", err)
	}
	if pr {
		// The head .shipguard.yaml is attacker-controlled on a PR; only the
		// base-ref policy that scan wrote may be used.
		return policy.Config{}, errors.New("policy.yaml missing on a PR: run `shipguard scan` first (the head config is not trusted)")
	}
	path := g.config
	if path == "" {
		path = filepath.Join(g.dir, ".shipguard.yaml")
	}
	return policy.Load(path)
}

func addReportFlags(cmd *cobra.Command, g *globals) {
	cmd.Flags().StringVar(&g.format, "format", "", "report format: sarif, gitlab, bitbucket or none (default: by platform)")
	cmd.Flags().BoolVar(&g.codeInsights, "code-insights", true, "publish Bitbucket Code Insights (CODE_INSIGHTS=false disables it)")
}

// reportCmd writes the platform report from .shipguard/findings.json. A
// config or findings error exits 2; an upload failure is only a warning.
func reportCmd(g *globals, getenv func(string) string, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Publish scan results to the CI platform",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return doReport(cmd.Context(), g, getenv, stderr)
		},
	}
	addReportFlags(cmd, g)
	return cmd
}

func doReport(ctx context.Context, g *globals, getenv func(string) string, stderr io.Writer) error {
	res, d, err := loadDecision(g)
	if err != nil {
		return err
	}
	env := getenv
	if !g.codeInsights {
		env = func(k string) string {
			if k == "CODE_INSIGHTS" {
				return "false"
			}
			return getenv(k)
		}
	}
	if err := report.Report(ctx, g.dir, g.format, res, d, env); err != nil {
		if errors.Is(err, report.ErrUpload) {
			fmt.Fprintf(stderr, "warning: %s\n", err)
			return nil
		}
		return fail(err)
	}
	return nil
}

// runCmd scans, gates and reports in one process. It returns the gate exit
// code, or 2 when scan failed. A failed scan wrote no findings, so gate and
// report are skipped; otherwise the report is always attempted.
func runCmd(g *globals, getenv func(string) string, stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Scan, gate, and report in one step",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			code := exitcode.Pass
			note := func(err error) {
				fmt.Fprintf(stderr, "error: %s\n", err)
				var ee *exitcode.Err
				c := exitcode.Error
				if errors.As(err, &ee) {
					c = ee.Code
				}
				code = max(code, c)
			}
			scanFailed := false
			if err := doScan(ctx, g, getenv, stdout, stderr); err != nil {
				note(err)
				scanFailed = true
				code = exitcode.Error
			}
			if scanFailed {
				fmt.Fprintln(stderr, "warning: scan failed; skipping gate and report")
			} else {
				if err := doGate(g, getenv, stdout); err != nil {
					note(err)
				}
				if err := doReport(ctx, g, getenv, stderr); err != nil {
					// the gate error, if any, already explained the failure
					if code == exitcode.Pass {
						note(err)
					} else {
						fmt.Fprintf(stderr, "warning: report: %s\n", err)
					}
				}
			}
			if code != exitcode.Pass {
				return &exitcode.Err{Code: code, Err: errors.New("run failed")}
			}
			return nil
		},
	}
	addReportFlags(cmd, g)
	return cmd
}

func versionCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the shipguard version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, err := fmt.Fprintln(stdout, version)
			return err
		},
	}
}
