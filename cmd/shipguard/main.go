// Command shipguard runs DevSecOps security scanners (secrets, SAST, SCA, IaC)
// in GitHub, GitLab, and Bitbucket pipelines and enforces a policy gate.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/faridlamaul/shipguard/internal/exitcode"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

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
		stubCmd("scan", "Run the configured scanners"),
		stubCmd("gate", "Apply the policy to the scan results"),
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
