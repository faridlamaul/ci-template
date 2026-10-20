package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/faridlamaul/shipguard/internal/finding"
	"github.com/faridlamaul/shipguard/internal/platform"
	"github.com/faridlamaul/shipguard/internal/policy"
)

// SARIFFile is the SARIF report path relative to the repository.
const SARIFFile = outDir + "/shipguard.sarif"

// Report writes the platform report for format: "" (auto from the detected
// platform), sarif, gitlab, bitbucket or none. Auto: github and local write
// SARIF, gitlab writes the GitLab reports into .shipguard/, bitbucket
// publishes Code Insights unless CODE_INSIGHTS=false. Bitbucket failures wrap
// ErrUpload.
//
// SHIPGUARD_BITBUCKET_PROXY overrides the proxy (unset or empty: the default
// Pipelines proxy; "none" disables it). SHIPGUARD_BITBUCKET_TOKEN is an
// optional Bearer token; with a token the proxy is not used.
func Report(ctx context.Context, dir, format string, r finding.Result, d policy.Decision, getenv func(string) string) error {
	pc := platform.Detect(getenv)
	if format == "" {
		switch pc.Platform {
		case "gitlab":
			format = "gitlab"
		case "bitbucket":
			format = "bitbucket"
		default:
			format = "sarif"
		}
	}
	switch format {
	case "none":
		return nil
	case "sarif":
		return writeSARIFFile(dir, r)
	case "gitlab":
		return WriteGitLab(filepath.Join(dir, outDir), r, r.ShipguardVersion, time.Now())
	case "bitbucket":
		if getenv("CODE_INSIGHTS") == "false" {
			return nil
		}
		return codeInsightsFromEnv(pc, getenv).Publish(ctx, r, d)
	}
	return fmt.Errorf("unknown report format %q (want sarif, gitlab, bitbucket or none)", format)
}

func codeInsightsFromEnv(pc platform.Context, getenv func(string) string) CodeInsights {
	proxy := getenv("SHIPGUARD_BITBUCKET_PROXY")
	switch proxy {
	case "":
		proxy = defaultBitbucketProxy
	case "none":
		proxy = ""
	}
	return CodeInsights{
		Proxy:  proxy,
		Token:  getenv("SHIPGUARD_BITBUCKET_TOKEN"),
		Repo:   pc.Repo,
		Commit: pc.HeadSHA,
	}
}

func writeSARIFFile(dir string, r finding.Result) error {
	path := filepath.Join(dir, SARIFFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create sarif: %w", err)
	}
	if err := WriteSARIF(f, r, r.ShipguardVersion); err != nil {
		_ = f.Close()
		return fmt.Errorf("write sarif: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close sarif: %w", err)
	}
	return nil
}
