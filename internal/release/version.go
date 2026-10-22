package release

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var tagRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

func setTag(r *Result, tag string) {
	r.Released, r.Tag, r.Version = true, tag, strings.TrimPrefix(tag, "v")
}

// headTag returns the release tag at HEAD, or "". With several vX.Y.Z tags the
// highest stable one wins, else the highest prerelease.
func headTag(ctx context.Context, o Options) string {
	out, err := o.Exec.Run(ctx, o.Dir, nil, io.Discard, "git", "tag", "--points-at", "HEAD", "--list", "v*")
	if err != nil {
		return ""
	}
	best := ""
	for _, tag := range strings.Fields(string(out)) {
		if tagRe.MatchString(tag) && (best == "" || tagLess(best, tag)) {
			best = tag
		}
	}
	return best
}

// tagLess orders valid release tags by semver precedence.
func tagLess(a, b string) bool {
	core := func(t string) ([3]int, string) {
		t = strings.TrimPrefix(t, "v")
		t, pre, _ := strings.Cut(t, "-")
		var n [3]int
		for i, p := range strings.SplitN(t, ".", 3) {
			n[i], _ = strconv.Atoi(p)
		}
		return n, pre
	}
	na, pa := core(a)
	nb, pb := core(b)
	if na != nb {
		for i := range na {
			if na[i] != nb[i] {
				return na[i] < nb[i]
			}
		}
	}
	switch {
	case pa == pb:
		return false
	case pa == "": // a stable release outranks its prereleases
		return false
	case pb == "":
		return true
	}
	ia, ib := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < len(ia) && i < len(ib); i++ {
		if ia[i] == ib[i] {
			continue
		}
		x, xerr := strconv.Atoi(ia[i])
		y, yerr := strconv.Atoi(ib[i])
		switch {
		case xerr == nil && yerr == nil:
			return x < y
		case xerr == nil: // numeric identifiers sort below alphanumeric ones
			return true
		case yerr == nil:
			return false
		}
		return ia[i] < ib[i]
	}
	return len(ia) < len(ib)
}

// resolveHeadTag is the version step without shiptag, used when it is not selected.
func resolveHeadTag(ctx context.Context, o Options, r *Result) {
	if tag := headTag(ctx, o); tag != "" {
		setTag(r, tag)
	} else if o.DryRun {
		r.Version = dryRunVersion
	}
}

// ensureTag creates tag locally at HEAD when it is missing; shiptag publishes
// through the platform API, so the checkout may not have it yet.
func ensureTag(ctx context.Context, o Options, tag string) error {
	if _, err := o.Exec.Run(ctx, o.Dir, nil, io.Discard, "git", "rev-parse", "-q", "--verify", "refs/tags/"+tag); err == nil {
		return nil
	}
	if _, err := o.Exec.Run(ctx, o.Dir, nil, o.Out, "git", "tag", tag, "HEAD"); err != nil {
		return fmt.Errorf("create local tag %s: %w", tag, err)
	}
	return nil
}

func version(ctx context.Context, o Options, r *Result) StepResult {
	shiptag, err := o.Tool(ctx, "shiptag")
	if err != nil {
		return StepResult{Status: "failed", Reason: err.Error()}
	}
	args := []string{"tag"}
	var outFile string
	if o.DryRun {
		args = append(args, "--dry-run", "--json")
	}
	if o.Prerelease != "" {
		args = append(args, "--prerelease", o.Prerelease)
	}
	if !o.DryRun {
		tmp, err := os.MkdirTemp("", "shipguard-release-")
		if err != nil {
			return StepResult{Status: "failed", Reason: err.Error()}
		}
		defer func() { _ = os.RemoveAll(tmp) }()
		outFile = filepath.Join(tmp, "shiptag.out")
		args = append(args, "--output-file", outFile)
	}
	stdout, err := o.Exec.Run(ctx, o.Dir, nil, o.Out, shiptag, args...)
	if err != nil {
		return StepResult{Status: "failed", Reason: "shiptag: " + err.Error()}
	}

	if o.DryRun {
		var plan struct {
			NextTag string `json:"next_tag"`
		}
		if json.Unmarshal(stdout, &plan) == nil && tagRe.MatchString(plan.NextTag) {
			r.Tag, r.Version = plan.NextTag, strings.TrimPrefix(plan.NextTag, "v")
			return StepResult{Status: "passed", Reason: "would release " + r.Tag}
		}
		if tag := headTag(ctx, o); tag != "" {
			setTag(r, tag)
			return StepResult{Status: "passed", Reason: "re-run: reusing " + tag + " at HEAD"}
		}
		r.Version = dryRunVersion
		return StepResult{Status: "passed", Reason: "nothing to release; using " + dryRunVersion}
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		return StepResult{Status: "failed", Reason: "shiptag wrote no outputs: " + err.Error()}
	}
	kv := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok {
			kv[k] = v
		}
	}

	if kv["released"] == "true" {
		tag := kv["tag"]
		if !tagRe.MatchString(tag) {
			return StepResult{Status: "failed", Reason: fmt.Sprintf("shiptag returned invalid tag %q", tag)}
		}
		if err := ensureTag(ctx, o, tag); err != nil {
			return StepResult{Status: "failed", Reason: err.Error()}
		}
		setTag(r, tag)
		return StepResult{Status: "passed", Reason: "released " + tag}
	}
	// Not released now: the release may already exist for HEAD (re-run).
	tag := kv["tag"]
	if !tagRe.MatchString(tag) {
		tag = headTag(ctx, o)
	}
	if tag != "" {
		if err := ensureTag(ctx, o, tag); err != nil {
			return StepResult{Status: "failed", Reason: err.Error()}
		}
		setTag(r, tag)
		return StepResult{Status: "passed", Reason: "re-run: reusing " + tag}
	}
	return StepResult{Status: "passed", Reason: "nothing to release"}
}
