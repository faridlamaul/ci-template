package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/faridlamaul/shipguard/internal/exitcode"
	"github.com/faridlamaul/shipguard/internal/policy"
	"github.com/faridlamaul/shipguard/internal/release"
	"github.com/faridlamaul/shipguard/internal/report"
)

// releaseExec runs the external commands of the release steps; tests replace it.
var releaseExec release.Exec = release.OSExec{}

// releaseToolResolver returns the tool lookup for the release steps; tests replace it.
var releaseToolResolver = func(dir string) (func(context.Context, string) (string, error), map[string]string, error) {
	return newToolResolverMsg(dir, runtime.GOOS, runtime.GOARCH, func(goos, goarch string) string {
		return fmt.Sprintf("pinned release tools are only available on linux (running on %s/%s); run shipguard release in a Linux CI runner", goos, goarch)
	})
}

var prereleaseRe = regexp.MustCompile(`^[0-9A-Za-z-]+$`)

// releaseInputs holds the release-local flag values.
type releaseInputs struct {
	dryRun     bool
	prerelease string
}

func releaseCmd(g *globals, getenv func(string) string, stdout, stderr io.Writer) *cobra.Command {
	in := &releaseInputs{}
	cmd := &cobra.Command{
		Use:   "release [version|binaries|image ...]",
		Short: "Version, publish binaries and publish a scanned, signed image",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doRelease(cmd.Context(), g, in, args, getenv, stdout, stderr)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&in.dryRun, "dry-run", false, "preview: build and scan the image, push and sign nothing")
	f.StringVar(&in.prerelease, "prerelease", "", "prerelease identifier passed to shiptag (for example rc)")
	return cmd
}

func doRelease(ctx context.Context, g *globals, in *releaseInputs, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if in.prerelease != "" && !prereleaseRe.MatchString(in.prerelease) {
		return fail(fmt.Errorf("--prerelease must match [0-9A-Za-z-]+, got %q", in.prerelease))
	}
	path := g.config
	if path == "" {
		path = ".shipguard.yaml"
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(g.dir, path)
	}
	cfg, err := policy.Load(path)
	if err != nil {
		return fail(err)
	}
	toolFn, _, err := releaseToolResolver(g.dir)
	if err != nil {
		return fail(err)
	}
	var outErr error
	res, err := release.Run(ctx, release.Options{
		Dir: g.dir, Config: cfg, Steps: args, DryRun: in.dryRun, Prerelease: in.prerelease,
		Tool: toolFn, Exec: releaseExec, Getenv: getenv, Out: stdout,
	})
	if len(res.Steps) > 0 {
		if werr := report.WriteRelease(g.dir, res); werr != nil {
			_, _ = fmt.Fprintf(stderr, "warning: write release results: %s\n", werr)
		}
		if werr := report.ReleaseOutputs(res, getenv); werr != nil {
			outErr = werr
		}
	}
	if err != nil {
		return fail(err)
	}
	if outErr != nil {
		_, _ = fmt.Fprintf(stderr, "error: write release outputs: %s\n", outErr)
		return &exitcode.Err{Code: exitcode.Fail, Err: errReported}
	}
	if code := res.ExitCode(); code != exitcode.Pass {
		return &exitcode.Err{Code: code, Err: errReported}
	}
	return nil
}
