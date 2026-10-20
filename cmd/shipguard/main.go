// Command shipguard runs DevSecOps security scanners (secrets, SAST, SCA, IaC)
// in GitHub, GitLab, and Bitbucket pipelines and enforces a policy gate.
package main

import (
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
}

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
	g := &globals{}
	root := &cobra.Command{
		Use:           "shipguard",
		Short:         "Security scanning and policy gate for GitHub, GitLab, and Bitbucket",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
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
		stubCmd("report", "Publish scan results to the CI platform"),
		stubCmd("run", "Scan, gate, and report in one step"),
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
		if val == "" && bitbucket {
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
			cats, err := scan.ParseCategories(g.scanners)
			if err != nil {
				return &exitcode.Err{Code: exitcode.Error, Err: err}
			}
			rulesDir := getenv("SHIPGUARD_RULES_DIR")
			if rulesDir == "" {
				rulesDir = defaultRulesDir
			}
			res, _, err := scan.Run(cmd.Context(), scan.Options{
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
				if r.Status == "error" {
					fmt.Fprintf(stderr, "warning: %s failed: %s\n", r.Name, r.Error)
				}
			}
			_, err = fmt.Fprintf(stdout, "shipguard scan: %d findings, results in %s\n",
				len(res.Findings), filepath.Join(g.dir, scan.OutDir, "findings.json"))
			return err
		},
	}
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
			fail := func(err error) error { return &exitcode.Err{Code: exitcode.Error, Err: err} }
			if g.mode != "" && g.mode != "enforce" && g.mode != "audit" {
				return fail(fmt.Errorf("--mode must be enforce or audit, got %q", g.mode))
			}
			out := filepath.Join(g.dir, scan.OutDir)
			res, err := finding.ReadResult(filepath.Join(out, "findings.json"))
			if err != nil {
				return fail(fmt.Errorf("%w (run `shipguard scan` first)", err))
			}
			cfg, err := gateConfig(g, out)
			if err != nil {
				return fail(err)
			}
			if g.mode != "" {
				cfg.Mode = g.mode
			}
			var pc platform.Context
			if len(res.Context) > 0 {
				if err := json.Unmarshal(res.Context, &pc); err != nil {
					return fail(fmt.Errorf("parse context in findings.json: %w", err))
				}
			}
			d := policy.Evaluate(res, cfg, pc.Event == platform.EventPR, now())

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
		},
	}
}

// gateConfig reads the effective config written by scan, falling back to the
// repository config when scan did not write one.
func gateConfig(g *globals, out string) (policy.Config, error) {
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
	path := g.config
	if path == "" {
		path = filepath.Join(g.dir, ".shipguard.yaml")
	}
	return policy.Load(path)
}

func stubCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return &exitcode.Err{Code: exitcode.Error, Err: errors.New("not implemented")}
		},
	}
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
