# shipguard Security Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `shipguard` Go CLI and container image that runs secrets, SAST, SCA and IaC scanning with a diff-aware policy gate, plus thin adapters for GitHub Actions, GitLab CI and Bitbucket Pipelines.

**Architecture:** One image holds the CLI and pinned scanners (gitleaks, opengrep, osv-scanner, trivy). `shipguard scan` normalizes scanner output into `.shipguard/findings.json`, `gate` applies `.shipguard.yaml`, and `report` writes the platform-native format. `shipguard run` does all three for adapters. The adapters in `adapters/{github,gitlab,bitbucket}` contain no logic beyond input mapping, history depth and report upload.

**Tech Stack:**
- Go 1.26 (`go.mod`), built and tested with Go 1.27.x in CI.
- Libraries: `spf13/cobra`, `gopkg.in/yaml.v3`, `bmatcuk/doublestar/v4`, and `santhosh-tekuri/jsonschema/v6` (tests only).
- Image: Alpine pinned by digest.
- Scanners: gitleaks, opengrep, osv-scanner v2, trivy.

**Spec:** `docs/superpowers/specs/2026-10-20-shipguard-security-scanning-design.md`. Read it, including §12 *Amendments*, before any task.

## Global Constraints

- Module path is `github.com/faridlamaul/shipguard`. Follow shiptag's layout and idioms:
  - `cmd/<name>/main.go` exposes `run(args []string, getenv func(string) string, stdout, stderr io.Writer) int`.
  - Packages live under `internal/`.
  - Errors are wrapped with `%w`.
  - Git-backed tests use the fixture helper (copied as `internal/testutil/gitfixture`).
- Exit codes: `0` pass or audit, `1` policy failure, `2` tool or config error. A scan that did not run is never a pass (fail closed), and that holds in `audit` mode too.
- Severities are exactly `critical | high | medium | low | info`. opengrep maps `ERROR→high`, `WARNING→medium`, `INFO→low`.
- Default policy: secrets `any`; sast `high`; sca `{severity: high, fix_available_only: true}`; iac `high`; mode `enforce`; `timeouts.per_scanner` `15m`.
- Secret values never appear in `findings.json`, raw copies kept by shipguard, logs, summaries or reports.
- Config keys are exactly those in spec §5.2. Unknown keys and exceptions without `reason`/`expires` are config errors (exit 2).
- On PR/MR the policy is read from the base ref.
- Output directory is `.shipguard/`. Scanner DB cache is `.shipguard-cache/`. Both, plus `.shipguard-action/`, `.git/` and `node_modules/`, are always excluded from scanning.
- Git tags are `vX.Y.Z`. Image tags are `vX.Y.Z`, `X.Y.Z`, `vX` and `vX.Y`. The gitlab.com Catalog project is tagged `X.Y.Z`.
- Every workflow:
  - pins actions by SHA with a `# vX.Y.Z` comment
  - uses `persist-credentials: false` unless it pushes
  - passes inputs to `run:` through `env:`, never `${{ }}` inside scripts
  - declares minimal `permissions`
- The existing reusable workflows (`go-ci`, `node-ci`, `python-ci`, `docker-build`, `go-release`, `semantic-release`) are not modified.
- Commits are signed (`git commit -S`), use Conventional Commits, and end with the `Co-Authored-By` line. Never push without the owner's approval.

## Review Focus

1. **A repository with no supported lockfile or no source files.** osv-scanner exits 128 ("no packages"). shipguard must treat that as zero findings, not an error. Test: `TestOSVNoPackagesIsEmpty` (Task 8).
2. **A PR whose base ref is not present locally**, for example a shallow clone or a GitHub branch name without `origin/`. Resolution tries `origin/<ref>`, then `<ref>`, then a fetch. If all fail, exit 2 with a message naming the ref; never fall back to a full-scan pass. Test: `TestScanPRMissingBaseFailsClosed` (Task 10).
3. **Thousands of findings.**
   - Bitbucket accepts at most 1000 annotations per report and 100 per request.
   - The GitHub step summary is limited to 1 MiB.
   - shipguard must batch annotations and truncate summaries with a "N more findings in .shipguard/findings.json" line.
   - Tests: `TestCodeInsightsBatchesAnnotations` (Task 14) and `TestSummaryTruncates` (Task 11).
4. **A PR that adds `.shipguard.yaml` when the base has none.** The base policy is the defaults, and the summary shows the "policy changed in this PR" warning. Test: `TestScanPRPolicyAddedUsesDefaults` (Task 10).
5. **An exception expiring today.** `expires: 2026-12-31` is valid through 2026-12-31 23:59:59 UTC and inactive from 2027-01-01 00:00 UTC. Test: `TestExceptionExpiryBoundary` (Task 4).

---

## Phase 0: Verification spike

### Task 0: Resolve verification items V1–V7

The owner needs to provide a Bitbucket workspace test repository, a gitlab.com project `faridlamaul/shipguard`, and a throwaway GitHub repository. Code written here is throwaway. Only `docs/verification.md` is kept.

**Files:**
- Create: `docs/verification.md` (one section per item: question, method, evidence such as a pipeline URL or log excerpt, result, chosen path)

- [ ] **Step 1: V4 and V5 (local).**
  - Run `osv-scanner scan source -r` on a directory containing only a `bun.lock`, and record whether packages are found.
  - Check the latest `opengrep/opengrep` release assets for `linux/arm64` (musl and glibc).
  - Expected: a documented yes or no for each.
- [ ] **Step 2: V1, V2, V3 (Bitbucket).**
  - In the test repository, run a step with `pipe: docker://ghcr.io/faridlamaul/shiptag:<current tag>`, then `@sha256:<digest>`.
  - Inside a custom test image used as a pipe, run `git fetch --unshallow` and `curl --proxy http://localhost:29418 -X PUT http://api.bitbucket.org/2.0/repositories/$BITBUCKET_REPO_FULL_NAME/commit/$BITBUCKET_COMMIT/reports/shipguard-spike`. If `localhost` fails, try `host.docker.internal`.
  - Expected: a documented working form for each, or the spec §10 fallback.
- [ ] **Step 3: V6 (GitLab).**
  - In the gitlab.com project, add `templates/scan.yml` with a `spec: inputs:` header.
  - From a second project, include it via `include: remote: https://gitlab.com/faridlamaul/shipguard/-/raw/<tag>/templates/scan.yml` with `inputs:` and `integrity:`.
  - Expected: the pipeline is created and the inputs are interpolated.
- [ ] **Step 4: V7 (GitHub).**
  - In the throwaway repository, call a reusable workflow from another repository and print `${{ job.workflow_sha }}` and `${{ job.workflow_ref }}`.
  - Also decode the OIDC token claims `job_workflow_sha` and `job_workflow_ref` (needs `id-token: write`).
  - Expected: the first mechanism that yields the called workflow's own SHA is recorded.
- [ ] **Step 5: Commit**

```bash
git add docs/verification.md
git commit -S -m "docs(verification): record spike results for V1-V7"
```

If any result contradicts spec §12, stop and bring it to the owner before Phase 3.

---

## Phase 1: CLI core

### Task 1: Module and CLI skeleton

**Files:**
- Create: `go.mod`, `cmd/shipguard/main.go`, `cmd/shipguard/main_test.go`, `internal/exitcode/exitcode.go`, `internal/testutil/gitfixture/gitfixture.go` (copy from shiptag, change only the import path), `Makefile` (shiptag's targets with `BINARY_NAME=shipguard`), `.gitignore` (`bin/`, `.shipguard/`, `.shipguard-cache/`)

**Interfaces:**
- Produces:
  - `exitcode.Pass = 0`, `exitcode.Fail = 1`, `exitcode.Error = 2`.
  - `type exitcode.Err struct{ Code int; Err error }` with `Error()` and `Unwrap()`.
  - `main.run(args []string, getenv func(string) string, stdout, stderr io.Writer) int` maps a returned `*exitcode.Err` to its code and any other error to 2.
  - Cobra root `shipguard` with persistent flags `--dir` (default: first non-empty of `GITHUB_WORKSPACE`, `CI_PROJECT_DIR`, `BITBUCKET_CLONE_DIR`, then cwd), `--config`, `--mode`, `--scanners`.
  - Subcommands `scan`, `gate`, `report`, `run` and `version` are registered. They are stubs until Tasks 10, 11 and 14.
- Flag env fallback: `--x-y` reads `SHIPGUARD_X_Y`. When `BITBUCKET_BUILD_NUMBER` is set it also reads the bare pipe variable (`SCANNERS`, `MODE`, `CONFIG`, `CODE_INSIGHTS`). An explicit flag wins over `SHIPGUARD_*`, which wins over the bare variable.

- [ ] **Step 1: Write failing tests.**
  - `TestVersionPrintsVersion`: `run([]string{"version"}, …)` returns 0 and stdout contains `dev`.
  - `TestUnknownCommandIsError`: returns 2.
  - `TestFlagEnvPrecedence`: a table over `--mode audit`, `SHIPGUARD_MODE=audit`, and `MODE=audit` with and without `BITBUCKET_BUILD_NUMBER=1`. It asserts the resolved mode.
- [ ] **Step 2: Run `go test ./cmd/...`.** Expected: FAIL (no package).
- [ ] **Step 3: Implement** `go.mod` (`go 1.26.0`, `require github.com/spf13/cobra`), the root command and the flag resolution in `cmd/shipguard/main.go`.
- [ ] **Step 4: Run `go test ./... && go vet ./...`.** Expected: PASS.
- [ ] **Step 5: Commit** with `git commit -S -m "feat(cli): add shipguard command skeleton and exit codes"`.

### Task 2: Finding model

**Files:**
- Create: `internal/finding/finding.go`, `internal/finding/fingerprint.go`, `internal/finding/filter.go`, `internal/finding/finding_test.go`

**Interfaces:**
- Produces:

```go
type Severity int // Critical=4, High=3, Medium=2, Low=1, Info=0; MarshalText/UnmarshalText lowercase
func ParseSeverity(s string) (Severity, error)
type Category string // "secrets" | "sast" | "sca" | "iac"
type Status string   // "" | "new" | "existing"
type Finding struct {
    ID           string   `json:"id"`        // rule id, CVE/GHSA, or "license:<SPDX>"
    Aliases      []string `json:"aliases,omitempty"`
    Scanner      string   `json:"scanner"`
    Category     Category `json:"category"`
    Severity     Severity `json:"severity"`
    File         string   `json:"file"`      // slash-separated, relative to repo root
    Line         int      `json:"line,omitempty"`
    Message      string   `json:"message"`
    Package      string   `json:"package,omitempty"`
    Version      string   `json:"version,omitempty"`
    FixedVersion string   `json:"fixed_version,omitempty"`
    FixAvailable bool     `json:"fix_available,omitempty"`
    Fingerprint  string   `json:"fingerprint"`
    Status       Status   `json:"status,omitempty"`
}
type ScannerRun struct { Name string; Category Category; Status string /* ok|error|skipped */; Error string; DurationMS int64 }
type Result struct { SchemaVersion int /* 1 */; ShipguardVersion string; Context json.RawMessage; Scanners []ScannerRun; Findings []Finding; PolicyChanged bool; PolicyDiff string }
func Fingerprint(ruleID, file, key string) string // hex sha256 of ruleID+"\x00"+file+"\x00"+normalize(key)
func NormalizeSnippet(s string) string            // collapse all whitespace runs to one space, trim
func SecretKey(secret string) string               // hex sha256 of the secret; the only form a secret may take
func FilterPaths(fs []Finding, exclude []string) []Finding // doublestar match on File; a pattern ending in "/" matches the prefix
func ReadResult(path string) (Result, error); func WriteResult(path string, r Result) error
```

- Fingerprint keys:
  - sast: the normalized snippet
  - sca: `package@version`
  - iac: the trivy resource name, or the normalized snippet
  - secrets: `SecretKey(secret)`
  - license: `package@version`

- [ ] **Step 1: Write failing tests.**
  - `TestSeverityRoundTrip`: all five values marshal to and from lowercase text, and `ParseSeverity("ERROR")` returns an error.
  - `TestFingerprintIgnoresLineAndWhitespace`: the same rule, file and snippet with different indentation give an equal fingerprint, and a different file gives a different one.
  - `TestFilterPaths`: `vendor/` drops `vendor/a/b.go`, `**/testdata/**` drops `x/testdata/y`, and `main.go` is kept.
  - `TestResultRoundTrip`: write then read returns an equal `Result`.
- [ ] **Step 2: Run `go test ./internal/finding/`.** Expected: FAIL.
- [ ] **Step 3: Implement** the files listed above.
- [ ] **Step 4: Run `go test ./internal/finding/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(finding): add unified finding model and fingerprints`.

### Task 3: Config loading, defaults and JSON Schema

**Files:**
- Create: `internal/policy/config.go`, `internal/policy/config_test.go`, `schema/shipguard.schema.json`, `schema/findings.schema.json`, `internal/policy/testdata/*.yaml`

**Interfaces:**
- Produces:

```go
type Threshold struct { Any bool; Severity finding.Severity; FixAvailableOnly bool } // YAML: "any" | "<severity>" | {severity, fix_available_only}
type Exception struct { ID, Path, Reason string; Expires time.Time } // YAML expires: YYYY-MM-DD
type Config struct {
    Version int; Mode string // "enforce" | "audit"
    Paths struct{ Exclude []string }
    Scanners struct {
        Secrets struct{ Enabled bool }
        SAST    struct{ Enabled bool; Rules, DisableRules []string }
        SCA     struct{ Enabled bool; Licenses struct{ Deny []string } }
        IaC     struct{ Enabled bool }
    }
    Timeouts struct{ PerScanner time.Duration }
    Policy struct{ FailOn map[finding.Category]Threshold }
    Exceptions []Exception
}
func Defaults() Config
func Parse(data []byte) (Config, error) // data merged over Defaults(); yaml.v3 Decoder.KnownFields(true)
func Load(path string) (Config, error)  // missing file → Defaults(), nil
var ErrConfig = errors.New("invalid config") // every validation error wraps it
```

- Validation:
  - `version` must be 1.
  - `mode` must be `enforce` or `audit`.
  - Each exception needs a non-empty `id`, `reason` and `expires`.
  - Unknown keys are rejected at every level.
- `schema/shipguard.schema.json` must accept every file in `internal/policy/testdata/valid/` and reject every file in `invalid/`.

- [ ] **Step 1: Write failing tests.**
  - `TestDefaultsMatchSpec`: asserts each default value listed in Global Constraints.
  - `TestParseRejectsUnknownKey`: `policy: {fail_ON: {}}` gives an error wrapping `ErrConfig`.
  - `TestParseRejectsExceptionWithoutExpires`.
  - `TestParseThresholdForms`: `any`, `high`, and `{severity: critical, fix_available_only: false}`.
  - `TestLoadMissingFileReturnsDefaults`.
  - `TestSchemaAgreesWithParser`: every testdata file gets the same accept/reject from `Parse` and from the JSON Schema (via jsonschema/v6).
- [ ] **Step 2: Run `go test ./internal/policy/`.** Expected: FAIL.
- [ ] **Step 3: Implement** `config.go` and both schemas. `findings.schema.json` describes `finding.Result`.
- [ ] **Step 4: Run `go test ./internal/policy/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(policy): load and validate .shipguard.yaml`.

### Task 4: Policy evaluation

**Files:**
- Create: `internal/policy/evaluate.go`, `internal/policy/evaluate_test.go`

**Interfaces:**
- Consumes: `Config` and `finding.Result` (Tasks 2 and 3).
- Produces:

```go
type Decision struct {
    Result     string            // "pass" | "fail" | "audit"
    Blocking   []finding.Finding // above threshold, not suppressed, and (not PR or Status=="new")
    Suppressed []finding.Finding
    Expired    []Exception       // matched a finding but past expiry
    New, Total int
    ScannerErrors []finding.ScannerRun
}
func Evaluate(r finding.Result, cfg Config, pr bool, now time.Time) Decision
func (d Decision) ExitCode() int // any ScannerErrors → 2; Blocking non-empty && mode enforce → 1; else 0
```

- An exception matches when `id` equals `Finding.ID`, one of its `Aliases`, or its `Fingerprint`, and (if set) `path` equals `Finding.File` or is a doublestar match.
- A license finding blocks only when its SPDX id is in `scanners.sca.licenses.deny`. Otherwise it is `info` and reported only.

- [ ] **Step 1: Write failing tests.**
  - `TestEvaluateDefaultThresholds` (table):
    - a secret of any severity blocks
    - sast `medium` does not block, `high` does
    - sca `high` without a fix does not block, `high` with a fix does
    - iac `critical` blocks
  - `TestEvaluatePRBlocksOnlyNew`: an `existing` high finding is not blocking on a PR but is blocking on a push.
  - `TestExceptionSuppressesByAlias`: exception `CVE-…` matches a finding with id `GHSA-…` and that CVE as an alias.
  - `TestExceptionExpiryBoundary`: now `2026-12-31T23:59:59Z` suppresses; `2027-01-01T00:00:00Z` does not and lists the exception in `Expired`.
  - `TestAuditModeExitZero`; `TestScannerErrorExitTwoEvenInAudit`; `TestLicenseDenyBlocks`.
- [ ] **Step 2: Run `go test ./internal/policy/ -run Evaluate\|Exception\|Audit\|ScannerError\|License`.** Expected: FAIL.
- [ ] **Step 3: Implement** `evaluate.go`.
- [ ] **Step 4: Run `go test ./internal/policy/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(policy): evaluate findings against thresholds and exceptions`.

### Task 5: Platform and event detection

**Files:**
- Create: `internal/platform/platform.go`, `internal/platform/platform_test.go`

**Interfaces:**
- Produces:

```go
type Event string // "pr" | "push" | "tag" | "schedule" | "manual"
type Context struct {
    Platform string // "github" | "gitlab" | "bitbucket" | "local"
    Event    Event
    HeadSHA, BaseRef, DefaultBranch, Repo string // BaseRef only for pr: branch name or SHA
}
func Detect(getenv func(string) string) Context
```

- Mapping:
  - **GitHub:**
    - `GITHUB_EVENT_NAME` `pull_request`/`pull_request_target` → pr, with BaseRef `GITHUB_BASE_REF`.
    - `schedule` → schedule.
    - `GITHUB_REF_TYPE=tag` → tag.
    - `workflow_dispatch` → manual.
    - otherwise push.
  - **GitLab:**
    - `CI_PIPELINE_SOURCE=merge_request_event` → pr, with BaseRef `CI_MERGE_REQUEST_DIFF_BASE_SHA`.
    - `schedule` → schedule.
    - `CI_COMMIT_TAG` set → tag.
    - `web`/`api` → manual.
    - otherwise push.
  - **Bitbucket:**
    - `BITBUCKET_PR_ID` set → pr, with BaseRef `BITBUCKET_PR_DESTINATION_BRANCH`.
    - `BITBUCKET_TAG` set → tag.
    - otherwise push.
- `SHIPGUARD_EVENT` overrides the detected event on any platform. Bitbucket exposes no schedule signal, so documentation tells scheduled custom pipelines to set `SHIPGUARD_EVENT=schedule`.

- [ ] **Step 1: Write failing tests.**
  - `TestDetect`: one table row per mapping above, plus `local` when no CI variables are set and the `SHIPGUARD_EVENT=schedule` override on Bitbucket.
- [ ] **Step 2: Run `go test ./internal/platform/`.** Expected: FAIL.
- [ ] **Step 3: Implement** `platform.go`.
- [ ] **Step 4: Run `go test ./internal/platform/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(platform): detect CI platform and event`.

### Task 6: Scanner interface, exec helper and gitleaks

**Files:**
- Create: `internal/scanner/scanner.go`, `internal/scanner/exec.go`, `internal/scanner/gitleaks.go`, `internal/scanner/gitleaks_test.go`, `internal/scanner/testdata/gitleaks/*.json`

**Interfaces:**
- Produces:

```go
type Target struct {
    Dir      string        // repo root (or base worktree)
    RawDir   string        // where raw output is written
    CacheDir string
    Exclude  []string
    Timeout  time.Duration
    // secrets
    LogOpts     string // e.g. "<base>..<head>" for PR; empty = directory scan
    FullHistory bool   // schedule: scan all of git history
    // sast
    Rules, DisableRules []string
    // sca
    DenyLicenses []string
}
type Scanner interface {
    Name() string
    Category() finding.Category
    Scan(ctx context.Context, t Target) ([]finding.Finding, error)
}
type Runner func(ctx context.Context, dir string, name string, args ...string) (stdout, stderr []byte, exitCode int, err error)
func ExecRunner() Runner                                            // os/exec; ctx carries the timeout
func Retry(ctx context.Context, attempts int, sleep func(time.Duration), fn func() error) error // backoff 1s, 2s, 4s
func NewGitleaks(run Runner) Scanner
func ParseGitleaks(raw []byte) ([]finding.Finding, error)
```

- gitleaks invocation:
  - LogOpts set: `gitleaks git --log-opts=<LogOpts>`.
  - FullHistory: `gitleaks git`.
  - otherwise: `gitleaks dir .`.
  - Always add `--report-format json --report-path <os.CreateTemp file outside Dir and RawDir> --exit-code 0 --no-banner`, without `--redact`, so the secret is available to hash.
- After parsing, delete the temporary report. Write `<RawDir>/gitleaks.json` as the parsed findings re-serialized, which contain no secret.
- Parsing: `RuleID`→`ID`, `File`, `StartLine`→`Line`, `Description`→`Message`; severity `high`; fingerprint key `SecretKey(Secret)`. `Secret`, `Match` and `Line` content are never copied into a `Finding`.
- Store the golden files from real gitleaks output in Task 0 or this task. They contain fake secrets only.

- [ ] **Step 1: Write failing tests.**
  - `TestParseGitleaks`: the golden file yields the expected IDs, files and lines. No field of any finding contains the literal fake secret from the fixture.
  - `TestGitleaksRawHasNoSecret`: after `Scan` with a fake Runner that writes the golden report, the temporary report is deleted and no file under RawDir contains the secret.
  - `TestGitleaksArgs`: a fake Runner records args for each mode (PR range, full history, dir).
  - `TestRetryBackoff`: three failures produce sleeps 1s and 2s and return the last error.
  - `TestScanTimeoutIsError`: a fake Runner that blocks until ctx is done gives an error, not an empty result.
- [ ] **Step 2: Run `go test ./internal/scanner/`.** Expected: FAIL.
- [ ] **Step 3: Implement** the files listed above.
- [ ] **Step 4: Run `go test ./internal/scanner/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(scanner): add scanner interface and gitleaks runner`.

### Task 7: opengrep runner

**Files:**
- Create: `internal/scanner/opengrep.go`, `internal/scanner/opengrep_test.go`, `internal/scanner/testdata/opengrep/*.json`

**Interfaces:**
- Consumes: `Scanner`, `Target`, `Runner` (Task 6).
- Produces: `NewOpengrep(run Runner, builtinRules string) Scanner` and `ParseOpengrep(raw []byte) ([]finding.Finding, error)`. `builtinRules` is `/opt/shipguard/rules` in the image.
- Invocation: `opengrep scan --json --output <RawDir>/opengrep.json --config <builtinRules> [--config <each Target.Rules>] [--exclude-rule <each DisableRules>] [--exclude <each Exclude>] --metrics=off .`
- Exit codes: anything other than 0 or 1 is an error.
- Parsing:
  - `check_id`→`ID`, `path`→`File`, `start.line`→`Line`, `extra.message`→`Message`.
  - Severity maps from `extra.severity` (opengrep `ERROR→high`, `WARNING→medium`, `INFO→low`).
  - Fingerprint key is `NormalizeSnippet(extra.lines)`.
  - Results listed in the JSON `errors` array become an error only when the array has entries of `level: error`.

- [ ] **Step 1: Write failing tests.**
  - `TestParseOpengrepSeverityMap`.
  - `TestOpengrepArgsIncludeConsumerRules`.
  - `TestOpengrepFatalErrorsAreErrors`: a golden file with a `level: error` entry gives an error.
- [ ] **Step 2: Run `go test ./internal/scanner/ -run Opengrep`.** Expected: FAIL.
- [ ] **Step 3: Implement** `opengrep.go`.
- [ ] **Step 4: Run `go test ./internal/scanner/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(scanner): add opengrep runner`.

### Task 8: osv-scanner runner

**Files:**
- Create: `internal/scanner/osv.go`, `internal/scanner/osv_test.go`, `internal/scanner/testdata/osv/*.json`

**Interfaces:**
- Produces: `NewOSV(run Runner) Scanner` and `ParseOSV(raw []byte) ([]finding.Finding, error)`.
- Invocation: `osv-scanner scan source -r --format json --output <RawDir>/osv.json .`. When `SHIPGUARD_OSV_OFFLINE_DB` is set, add `--offline-vulnerabilities --local-db-path <that>`.
- Exit codes:
  - 0 and 1 are normal.
  - **128 means no packages found, which is zero findings and not an error.**
  - Anything else is an error.
- The whole run is retried with `Retry(…, 3, …)` on error exits.
- Parsing (one finding per package × vulnerability):
  - `ID` is the vulnerability id, and `Aliases` are its aliases.
  - `File` is the lockfile path relative to Dir.
  - `Package` and `Version` come from the package.
  - `FixedVersion` is the first `fixed` event in the affected ranges for that package. `FixAvailable` is true when it is non-empty.
  - Severity comes from the group's `max_severity` CVSS score: ≥9.0 critical, ≥7.0 high, ≥4.0 medium, >0 low, missing → medium.
  - Fingerprint key is `package@version`.

- [ ] **Step 1: Write failing tests.**
  - `TestParseOSVFixAvailable`: a golden file has one fixed vulnerability and one unfixed.
  - `TestOSVSeverityFromCVSS` (table on the score bands).
  - `TestOSVNoPackagesIsEmpty`: a fake Runner returning exit 128 gives zero findings and nil error.
  - `TestOSVExit127IsError`.
- [ ] **Step 2: Run `go test ./internal/scanner/ -run OSV`.** Expected: FAIL.
- [ ] **Step 3: Implement** `osv.go`.
- [ ] **Step 4: Run `go test ./internal/scanner/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(scanner): add osv-scanner runner`.

### Task 9: trivy runners (IaC and licenses)

**Files:**
- Create: `internal/scanner/trivy.go`, `internal/scanner/trivy_test.go`, `internal/scanner/testdata/trivy/*.json`

**Interfaces:**
- Produces:
  - `NewTrivyConfig(run Runner) Scanner` with category `iac`.
  - `NewTrivyLicense(run Runner) Scanner` with category `sca` and name `trivy-license`.
  - `ParseTrivyConfig(raw []byte)` and `ParseTrivyLicense(raw []byte, deny []string)`, both returning `([]finding.Finding, error)`.
- DB setup before the first trivy scan: `trivy fs --download-db-only --cache-dir <CacheDir>/trivy`, wrapped in `Retry(3)`. When `SHIPGUARD_TRIVY_DB_REPOSITORY` is set, add `--db-repository <that>`. If it still fails, the scanner returns an error.
- Invocations:
  - `trivy config --format json --output <RawDir>/trivy-config.json --skip-dirs <Exclude dirs> --exit-code 0 .`
  - `trivy fs --scanners license --format json --output <RawDir>/trivy-license.json --exit-code 0 .`
  - Both use `--cache-dir <CacheDir>/trivy --skip-db-update`.
- Parsing:
  - **Config:** each `Results[].Misconfigurations[]` with `Status=="FAIL"` becomes a finding. `ID` is the `AVDID` (fallback `ID`), `File` is `Target`, `Line` is `CauseMetadata.StartLine`, severity is lowercase, and the fingerprint key is `CauseMetadata.Resource` (fallback the normalized `Title`).
  - **License:** `ID` is `license:<Name>`, `Package` is `PkgName`, `File` is `FilePath`. Severity is `high` when `Name` is in deny, otherwise `info`.

- [ ] **Step 1: Write failing tests.**
  - `TestParseTrivyConfigOnlyFailures`.
  - `TestParseTrivyLicenseDeny`: `AGPL-3.0` in deny is high, MIT is info.
  - `TestTrivyDBDownloadRetriesThenErrors`: a fake Runner always fails, giving 3 attempts and then an error.
- [ ] **Step 2: Run `go test ./internal/scanner/ -run Trivy`.** Expected: FAIL.
- [ ] **Step 3: Implement** `trivy.go`.
- [ ] **Step 4: Run `go test ./internal/scanner/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(scanner): add trivy config and license runners`.

### Task 10: `scan` command with diff-aware scanning

**Files:**
- Create: `internal/gitx/gitx.go`, `internal/gitx/gitx_test.go`, `internal/scan/scan.go`, `internal/scan/scan_test.go`
- Modify: `cmd/shipguard/main.go` (wire `scan`)

**Interfaces:**
- Consumes: Tasks 2–9.
- Produces:

```go
// gitx
func ResolveRef(dir, ref string) (sha string, err error) // tries origin/<ref>, <ref>, then `git fetch origin <ref>` and retries; error names the ref
func IsShallow(dir string) (bool, error)
func Unshallow(dir string) error
func Worktree(dir, sha string) (path string, cleanup func(), err error) // `git worktree add --detach` into a temp dir
func Show(dir, sha, path string) ([]byte, bool, error)                  // file at revision; false if absent
func Diff(dir, base, head, path string) (string, error)

// scan
type Options struct { Dir, ConfigPath string; Categories []finding.Category; Ctx platform.Context; Scanners []scanner.Scanner; Now func() time.Time }
func Run(ctx context.Context, o Options) (finding.Result, policy.Config, error) // also writes .shipguard/findings.json and .shipguard/raw/
```

- Behaviour of `Run`:
  1. If the event is `pr`, resolve the base SHA with `ResolveRef` (error → exit 2). On Bitbucket, unshallow first when shallow.
  2. Load the effective config.
     - On a PR, use `Show(base, configPath)` parsed with `policy.Parse`, falling back to `Defaults()` when absent.
     - On a PR, set `PolicyChanged` when the head bytes differ from the base bytes, and fill `PolicyDiff`.
     - Otherwise use `Load(head)`.
  3. Run each enabled scanner on head with `Timeout = cfg.Timeouts.PerScanner`, recording a `ScannerRun` for each. Errors are recorded and `Run` continues; it does not abort.
  4. Secrets target:
     - pr: `LogOpts = base..HEAD`
     - schedule: `FullHistory`
     - otherwise: directory scan.
  5. On a PR, for sast, sca and iac, scan the base worktree with the same scanners. Mark head findings `new` when their fingerprint is absent from the base set, `existing` otherwise. Secrets are always `new` on a PR.
  6. Apply `FilterPaths` with the config excludes plus the always-excluded paths from Global Constraints.
  7. Write `findings.json`.

- [ ] **Step 1: Write failing tests** (use gitfixture repos and fake `Scanner`s that return canned findings keyed by dir):
  - `TestScanPRMarksNewAndExisting`.
  - `TestScanPRUsesBasePolicy`: head's `.shipguard.yaml` sets `mode: audit` and base sets `enforce`, so the effective mode is `enforce` and `PolicyChanged` is true.
  - `TestScanPRPolicyAddedUsesDefaults`.
  - `TestScanPRMissingBaseFailsClosed`: base ref `nope` gives an error containing `nope`.
  - `TestScanScannerErrorRecorded`: one fake scanner fails, so the result has `ScannerRun.Status=="error"` and the other findings are present.
  - `TestScanAppliesExcludes`.
  - `TestResolveRefOriginPrefix` (in gitx).
- [ ] **Step 2: Run `go test ./internal/gitx/ ./internal/scan/`.** Expected: FAIL.
- [ ] **Step 3: Implement** gitx, scan and the `scan` subcommand.
  - The `--scanners` flag takes `all` or a comma list from `secrets,sast,sca,iac`.
  - Wiring builds the real scanners with `ExecRunner()`.
- [ ] **Step 4: Run `go test ./...`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(scan): run scanners with diff-aware PR mode`.

### Task 11: `gate` command, summary and outputs

**Files:**
- Create: `internal/report/summary.go`, `internal/report/summary_test.go`, `internal/report/outputs.go`, `internal/report/outputs_test.go`
- Modify: `cmd/shipguard/main.go` (wire `gate`)

**Interfaces:**
- Consumes: `policy.Evaluate`, `finding.ReadResult`.
- Produces:
  - `func Summary(r finding.Result, d policy.Decision, maxBytes int) string`
  - `func WriteOutputs(dir string, d policy.Decision, getenv func(string) string) error`, which always writes `.shipguard/gate.env` (`SHIPGUARD_RESULT=`, `SHIPGUARD_NEW_FINDINGS=`, `SHIPGUARD_TOTAL_FINDINGS=`) and also appends `result=`, `new_findings=` and `total_findings=` to `$GITHUB_OUTPUT` when it is set.
- Summary (Markdown), in this order:
  1. A result line.
  2. The "⚠ Policy changed in this PR" block with the diff when `PolicyChanged` is set.
  3. Scanner errors.
  4. A table of blocking findings (severity, category, id, file:line).
  5. Expired exceptions.
  6. Counts of existing, suppressed and below-threshold findings.
  - When it exceeds `maxBytes`, truncate the table and append `…and N more findings in .shipguard/findings.json`.
  - The `gate` command writes `.shipguard/summary.md` with no limit, and appends a copy limited to 1,000,000 bytes to `$GITHUB_STEP_SUMMARY` when that is set.
  - It prints the summary to stdout and returns `Decision.ExitCode()`.

- [ ] **Step 1: Write failing tests.**
  - `TestSummaryShowsPolicyChange`.
  - `TestSummaryTruncates`: 5000 findings with `maxBytes=10000` give a length ≤ 10000 and a "more findings" line.
  - `TestWriteOutputsGitHubAndDotenv`.
  - `TestGateExitCodes` in `cmd/shipguard`: from canned `findings.json` files, the results are 0, 1 and 2.
- [ ] **Step 2: Run `go test ./internal/report/ ./cmd/...`.** Expected: FAIL.
- [ ] **Step 3: Implement** summary.go, outputs.go and the `gate` subcommand.
- [ ] **Step 4: Run `go test ./...`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(gate): add policy gate, summary and CI outputs`.

### Task 12: SARIF report

**Files:**
- Create: `internal/report/sarif.go`, `internal/report/sarif_test.go`, `internal/report/testdata/sarif-schema-2.1.0.json` (vendored from the OASIS SARIF repository)

**Interfaces:**
- Produces: `func WriteSARIF(w io.Writer, r finding.Result, version string) error`.
- SARIF structure:
  - One run with `tool.driver.name = "shipguard"`, the shipguard version, and `rules` deduplicated by ID.
  - `level`: critical and high → `error`, medium → `warning`, low and info → `note`.
  - Each rule's `properties["security-severity"]`: critical `"9.5"`, high `"8.0"`, medium `"5.5"`, low `"3.0"`, info `"0.0"`.
  - `partialFingerprints["shipguard/v1"]` is the Fingerprint.
  - Location: `File`, with `Line` defaulting to 1.
  - `properties.status` is `Status`.

- [ ] **Step 1: Write failing tests.**
  - `TestSARIFValidatesAgainstSchema`.
  - `TestSARIFLevelsAndSecuritySeverity`.
  - `TestSARIFDedupesRules`.
- [ ] **Step 2: Run `go test ./internal/report/ -run SARIF`.** Expected: FAIL.
- [ ] **Step 3: Implement** `sarif.go`.
- [ ] **Step 4: Run `go test ./internal/report/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(report): add SARIF output`.

### Task 13: GitLab security reports

**Files:**
- Create: `internal/report/gitlab.go`, `internal/report/gitlab_test.go`, `internal/report/testdata/gitlab/*.json` (official schemas from `gitlab-org/security-products/security-report-schemas`, pinned to the latest 15.x tag at implementation time and recorded in a `SOURCE` file)

**Interfaces:**
- Produces: `func WriteGitLab(dir string, r finding.Result, version string, now time.Time) error`, which writes three files under `dir`:
  - `gl-secret-detection-report.json` (secrets)
  - `gl-sast-report.json` (sast and iac)
  - `gl-dependency-scanning-report.json` (sca, including licenses with severity ≥ low)
- Each file is written even when it has no findings.
- Required fields:
  - `scan.analyzer` and `scan.scanner` are `{id: "shipguard", name: "shipguard", version, vendor: {name: "shipguard"}}`.
  - `scan.status` is `success`, or `failure` when that category's scanner errored.
  - `vulnerabilities[].id` is the Fingerprint, `identifiers` contains the ID and its aliases, and `severity` is capitalized (`Critical`, … `Info`).

- [ ] **Step 1: Write failing tests.**
  - `TestGitLabReportsValidate`: all three files validate against their vendored schema.
  - `TestGitLabIaCGoesToSAST`.
  - `TestGitLabEmptyReportsWritten`.
- [ ] **Step 2: Run `go test ./internal/report/ -run GitLab`.** Expected: FAIL.
- [ ] **Step 3: Implement** `gitlab.go`.
- [ ] **Step 4: Run `go test ./internal/report/`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(report): add GitLab security reports`.

### Task 14: Bitbucket Code Insights, `report` and `run` commands

**Files:**
- Create: `internal/report/bitbucket.go`, `internal/report/bitbucket_test.go`, `internal/report/report.go`
- Modify: `cmd/shipguard/main.go` (wire `report` and `run`)

**Interfaces:**
- Produces:

```go
type CodeInsights struct { BaseURL string /* default "http://api.bitbucket.org/2.0" */; Proxy string /* from Task 0 V3, default "http://localhost:29418" */; Token string; Repo, Commit string; HTTP *http.Client }
func (c CodeInsights) Publish(ctx context.Context, r finding.Result, d policy.Decision) error
// PUT /repositories/{Repo}/commit/{Commit}/reports/shipguard  (result PASSED|FAILED, details = first summary line)
// POST .../reports/shipguard/annotations in batches of ≤100, at most 1000 annotations total (blocking first, then by severity)
func Report(ctx context.Context, dir, format string, r finding.Result, d policy.Decision, getenv func(string) string) error
// format "" = auto from platform.Detect: github → .shipguard/shipguard.sarif; gitlab → WriteGitLab(.shipguard); bitbucket → Publish unless CODE_INSIGHTS=false; local → sarif
// Explicit format values: sarif | gitlab | bitbucket | none
```

- Upload failures:
  - A Bitbucket API error returns a value wrapped in `report.ErrUpload`.
  - The `report` command prints a warning for it and exits 0.
- The `run` command:
  1. Runs scan, then gate, then report.
  2. Always attempts report, even when gate returned 1 or 2.
  3. Returns the gate exit code, or 2 if scan itself returned an error (scan still writes partial results).

- [ ] **Step 1: Write failing tests.**
  - `TestCodeInsightsBatchesAnnotations`: 2500 findings against an httptest server give 1 PUT, 10 POSTs and 1000 annotations total.
  - `TestCodeInsightsUsesProxy`.
  - `TestReportUploadFailureIsWarning`.
  - `TestRunAlwaysReports`: a fake failing gate still produces a SARIF file, and the exit is 1.
- [ ] **Step 2: Run `go test ./internal/report/ ./cmd/...`.** Expected: FAIL.
- [ ] **Step 3: Implement** bitbucket.go, report.go and the commands.
- [ ] **Step 4: Run `go test -race ./... && go vet ./...`.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(report): add Bitbucket Code Insights and run command`.

---

## Phase 2: Rules, image and end-to-end

### Task 15: Curated opengrep ruleset

**Files:**
- Create:
  - `rules/<lang>/<rule>.yaml` and `rules/<lang>/<rule>.<ext>` test targets for `go`, `javascript` (covers TS), `python`, `ruby` and `rust`
  - `rules/LICENSE` (MIT)
  - `rules/README.md` (rule id convention `shipguard.<lang>.<name>`, severity guidance: ERROR only for directly exploitable patterns)

- Coverage per language, where the language has the construct:
  - command injection
  - SQL injection (string-built queries)
  - path traversal
  - SSRF (user input into an HTTP client URL)
  - unsafe deserialization (`pickle`, `yaml.load`, `Marshal.load`, `node-serialize`)
  - weak hash/crypto (md5/sha1 for security, DES/RC4)
  - TLS verification disabled
  - hard-coded credentials
  - `eval` / `unsafe` / `exec`
- Every rule's test target contains at least one `# ruleid:` line and one `# ok:` line.

- [ ] **Step 1: Write the test targets first** (`ruleid:` and `ok:` annotated code) for one language.
- [ ] **Step 2: Run `opengrep test rules/<lang>/` (opengrep from `versions.env`).** Expected: FAIL (no rules).
- [ ] **Step 3: Write the rules** for that language.
- [ ] **Step 4: Run `opengrep test rules/`.** Expected: all pass. Repeat steps 1–4 per language.
- [ ] **Step 5: Commit** each language as `feat(rules): add <lang> security rules`.

### Task 16: Image, pinned scanners and update automation

**Files:**
- Create:
  - `versions.env` (`<TOOL>_VERSION`, `<TOOL>_SHA256_AMD64`, `<TOOL>_SHA256_ARM64` for `GITLEAKS`, `OPENGREP`, `OSV_SCANNER`, `TRIVY`; latest releases at implementation time)
  - `scripts/install-scanners.sh` (args: `TARGETARCH`; sources `versions.env`; downloads each asset; `sha256sum -c` must pass or the build fails; installs to `/usr/local/bin`)
  - `scripts/bump-scanners.sh` (for each tool: latest release via `gh api`, recompute checksums from the upstream checksums file and verify against the downloaded asset, rewrite `versions.env`)
  - `Dockerfile`
  - `.dockerignore`
  - `.github/workflows/bump-scanners.yml`

- Dockerfile requirements:
  - Builder stage `golang:1.27-alpine` builds `/shipguard` with `-trimpath -ldflags "-s -w -X main.version=${VERSION}"`.
  - Scanner stage runs `install-scanners.sh "$TARGETARCH"`.
  - Final stage is `alpine:3.24@sha256:<digest>` with `git` and `ca-certificates`, and `git config --system --add safe.directory '*'`.
  - It copies the binaries plus `rules/` to `/opt/shipguard/rules`.
  - It runs as root on purpose; copy shiptag's Dockerfile comment explaining why (spec §12 A1).
  - `ENTRYPOINT ["shipguard"]` and `CMD ["run"]`.
  - Builds for `linux/amd64` and `linux/arm64`, unless V5 found no arm64 opengrep, in which case amd64 only.
- `bump-scanners.yml`:
  - Weekly schedule plus `workflow_dispatch`, with `contents: write` and `pull-requests: write`.
  - It runs the bump script, then `make test` and the image E2E (Task 17), then opens the PR.
  - A comment notes that PRs opened with `GITHUB_TOKEN` do not trigger CI, which is why tests run here first.

- [ ] **Step 1: Write the failing check.**
  - Make target `image-test`: `docker build -t shipguard:dev .`, then `docker run --rm shipguard:dev version` and `docker run --rm --entrypoint sh shipguard:dev -c 'gitleaks version && opengrep --version && osv-scanner --version && trivy --version'`.
  - Run `make image-test`. Expected: FAIL (no Dockerfile).
- [ ] **Step 2: Implement** `versions.env`, the scripts and the Dockerfile.
- [ ] **Step 3: Corrupt one checksum** in a scratch copy of `versions.env` and build. Expected: the build fails at `sha256sum -c`. Then restore it.
- [ ] **Step 4: Run `make image-test`.** Expected: PASS and all four versions printed.
- [ ] **Step 5: Commit** with `build(image): add shipguard image with pinned scanners`.

### Task 17: Fixtures and image E2E

**Files:**
- Create: `testdata/fixtures/{go,node,python,ruby,rust}/…`, `testdata/fixtures/<lang>/expected.json`, `e2e/e2e_test.go` (build tag `e2e`; image from `SHIPGUARD_IMAGE`)

- Each fixture contains:
  - a lockfile with at least one dependency that has a known **fixed** high or critical vulnerability
  - source code hitting at least one shipguard rule
  - at least one `Dockerfile` without `USER` (only one fixture is required)
- **No secret is committed.** The test writes the fake secret into a temporary copy at runtime by concatenating string pieces, so neither GitHub push protection nor dogfood scans flag the repository.
- `expected.json` lists `{category, id}` pairs that must be a **subset** of the findings, because SCA results grow as the vulnerability databases change.

- [ ] **Step 1: Write failing tests.**
  - `TestFixtureFindings/<lang>`: copy the fixture to a temp dir, `git init` and commit, add the runtime secret, then `docker run -v <tmp>:/src -w /src $SHIPGUARD_IMAGE run --dir /src`. Expect exit 1, a `findings.json` that contains `expected.json`, and the secret string absent from every file under `.shipguard/`.
  - `TestPRDiffAware`: commit a clean base on `main`, branch, and add one SAST hit. Run with `GITHUB_ACTIONS=true`, `GITHUB_EVENT_NAME=pull_request` and `GITHUB_BASE_REF=main`. Expect exactly the new hit to be `new`, and the fixture's existing findings `existing` and not blocking.
  - `TestNoLockfileRepoPasses`: a repo with only a README gives exit 0.
- [ ] **Step 2: Run `SHIPGUARD_IMAGE=shipguard:dev go test -tags e2e ./e2e/`.** Expected: FAIL (no fixtures).
- [ ] **Step 3: Add the fixtures** and `expected.json`.
- [ ] **Step 4: Run the same command.** Expected: PASS.
- [ ] **Step 5: Commit** with `test(e2e): add vulnerable fixtures and image tests`.

---

## Phase 3: Adapters

### Task 18: GitHub adapter and reusable workflow

**Files:**
- Create: `adapters/github/action.yml`, `.github/workflows/scan.yml`, `.github/workflows/adapter-github.yml` (self-test)

**Interfaces:**
- Composite action:
  - Inputs: `scanners` (default `all`), `mode` (default `""`), `config` (default `.shipguard.yaml`), `image` (default `""`), `upload_sarif` (default `auto`).
  - Outputs: `result`, `new_findings`, `total_findings`.
- Composite steps:
  1. **Resolve the image.** If `inputs.image` is set, use it. Else, if `github.action_ref` matches `^v\d+(\.\d+){0,2}$`, use `ghcr.io/faridlamaul/shipguard:<action_ref>`. Else run `docker build -t shipguard:local "$GITHUB_ACTION_PATH/../.."`.
  2. **Restore the cache.** `actions/cache` on `.shipguard-cache`, with a key of OS plus ISO week.
  3. **Run the image.** `docker run --rm -v "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE" -v "$RUNNER_TEMP:$RUNNER_TEMP" -w "$GITHUB_WORKSPACE" --env-file <(env | grep -E '^(GITHUB_|RUNNER_|SHIPGUARD_|CI=)') -e SHIPGUARD_SCANNERS -e SHIPGUARD_MODE -e SHIPGUARD_CONFIG <image> run`, then record the exit code in a step output and do not fail the step yet.
  4. **Upload SARIF.** `github/codeql-action/upload-sarif` when `upload_sarif != 'false'` and the file exists, with `continue-on-error: ${{ inputs.upload_sarif == 'auto' }}`.
  5. **Exit** with the recorded code.
- Reusable `scan.yml`:
  - `on: workflow_call` with the same inputs and outputs.
  - Job permissions `contents: read`, `security-events: write`, plus `id-token: write` only if V7 chose OIDC.
  - Steps:
    1. Checkout the caller with `fetch-depth: 0` and `persist-credentials: false`.
    2. Resolve its own SHA by the V7 mechanism.
    3. Checkout `faridlamaul/shipguard` at that SHA to `.shipguard-action` (`persist-credentials: false`).
    4. `uses: ./.shipguard-action/adapters/github` with the inputs. When the workflow ref is a `vX.Y.Z` tag, pass `image: ghcr.io/faridlamaul/shipguard:<tag>` so SHA-pinned callers do not rebuild.
- `adapter-github.yml` (on `pull_request`):
  - Job A: `uses: ./.github/workflows/scan.yml` on this repository with `mode: audit`, expecting `result == 'audit'`.
  - Job B: runs the composite against a fixture copy, expecting `result == 'fail'`.
  - Both assert via a follow-up job on `needs.<job>.outputs.result`.

- [ ] **Step 1: Write `adapter-github.yml` first** and run `actionlint` and `zizmor .github/ adapters/github/`. Expected: actionlint reports the missing called workflow.
- [ ] **Step 2: Implement** the composite action and `scan.yml`.
- [ ] **Step 3: Run `actionlint && zizmor --min-severity medium .github/ adapters/github/`.** Expected: no findings.
- [ ] **Step 4: Push the branch** (with the owner's approval) and open a draft PR. Expected: both self-test jobs green, with SARIF visible in Code Scanning (the repository is public).
- [ ] **Step 5: Commit** with `feat(adapters): add GitHub composite action and reusable workflow`.

### Task 19: GitLab adapter and renderer

**Files:**
- Create: `adapters/gitlab/scan.yml`, `scripts/render-gitlab.sh` (args: `VERSION` such as `1.2.3` and an output dir; copies `adapters/gitlab/*.yml` and replaces the single placeholder `__SHIPGUARD_VERSION__` with `v$VERSION`), `adapters/gitlab/test/.gitlab-ci.yml` (used by the publish project's smoke test)

**Interfaces:**
- `scan.yml` `spec.inputs`:
  - `scanners` (default `all`), `mode` (default `""`), `config` (default `.shipguard.yaml`)
  - `image` (default `ghcr.io/faridlamaul/shipguard:__SHIPGUARD_VERSION__`)
  - `stage` (default `test`)
- Job `shipguard`:
  - `image: {name: $[[ inputs.image ]], entrypoint: [""]}`
  - variables: `GIT_DEPTH: "0"`, `SHIPGUARD_SCANNERS`, `SHIPGUARD_MODE`, `SHIPGUARD_CONFIG`
  - `script: [shipguard run]`
  - `cache: {key: shipguard-db, paths: [.shipguard-cache/]}`
  - `artifacts: {when: always, paths: [.shipguard/], reports: {sast: .shipguard/gl-sast-report.json, dependency_scanning: .shipguard/gl-dependency-scanning-report.json, secret_detection: .shipguard/gl-secret-detection-report.json, dotenv: .shipguard/gate.env}}`
  - `rules`: MR events, default branch, tags, schedules
- No component-only syntax (`$[[ component.* ]]`).

- [ ] **Step 1: Write a failing check.**
  - Make target `gitlab-lint`: render to `dist/gitlab`, then POST each file to `https://gitlab.com/api/v4/projects/<test project id>/ci/lint` via `glab api` with `include_jobs=true`.
  - Expected: FAIL (no file).
- [ ] **Step 2: Implement** `scan.yml` and the renderer.
- [ ] **Step 3: Run `make gitlab-lint`.** Expected: `valid: true`, with no placeholder left in `dist/gitlab`.
- [ ] **Step 4: Commit** with `feat(adapters): add GitLab job template`.

### Task 20: Bitbucket adapter

**Files:**
- Create: `adapters/bitbucket/pipe.yml` (Atlassian pipe metadata: `name`, `image: ghcr.io/faridlamaul/shipguard:__SHIPGUARD_VERSION__`, `category: Security`, `description`, `repository`, `maintainer`, `variables` for `SCANNERS`, `MODE`, `CONFIG` and `CODE_INSIGHTS` with defaults), `adapters/bitbucket/README.md`, `adapters/bitbucket/test/bitbucket-pipelines.yml` (for the Bitbucket test repository)

- The image's default `CMD ["run"]` serves as the pipe entrypoint.
- Variable mapping and unshallow behaviour are already in the CLI (Tasks 1 and 10).
- The README documents:
  - the variables
  - `SHIPGUARD_EVENT=schedule` for scheduled custom pipelines
  - the V2 outcome (whether `clone: depth: full` is needed)
  - the V3 outcome (proxy host)

- [ ] **Step 1: Push `adapters/bitbucket/test/bitbucket-pipelines.yml`** to the Bitbucket test repository with a fixture copy and a step using `pipe: docker://ghcr.io/faridlamaul/shipguard:<pre-release tag from Task 22, or a dev tag pushed manually>`. Expected: before this task's CLI fixes the step fails, or the report is absent.
- [ ] **Step 2: Fix any gaps** found in the CLI's Bitbucket paths, with unit tests for each fix.
- [ ] **Step 3: Rerun the pipeline.** Expected: the step fails with exit 1 (fixture has findings), the Code Insights report is shown on the commit, and on a PR only new findings block.
- [ ] **Step 4: Commit** with `feat(adapters): add Bitbucket pipe metadata`.

---

## Phase 4: Repository CI, release and docs

### Task 21: Repository CI and dogfooding

**Files:**
- Modify: `.github/workflows/ci.yml` (keep the actionlint job)
- Modify: `.github/dependabot.yml`
- Create: `.shipguard.yaml` (this repository's own policy; excludes `testdata/`, `rules/**/*.go|*.py|*.js|*.rb|*.rs` test targets and `e2e/`)

- Add these jobs to `ci.yml`, modelled on shiptag's:
  - `test`: gofmt check, `go vet`, `go test -race ./...`, govulncheck
  - `rules`: `opengrep test rules/` using the version from `versions.env`
  - `image`: build plus `make image-test`
  - `e2e`: needs image; loads it, then runs `go test -tags e2e ./e2e/`
  - `zizmor`: `zizmor --min-severity medium .github/ adapters/github/` via the pinned image
  - `dogfood`: `uses: ./.github/workflows/scan.yml`
- `dependabot.yml`: add `gomod` (`/`) and `docker` (`/`) ecosystems with `fix(deps)` prefixes, keeping the existing `github-actions` entry.

- [ ] **Step 1: Implement.**
- [ ] **Step 2: Run `actionlint` and `zizmor` locally.** Expected: clean.
- [ ] **Step 3: Push** (with approval). Expected: all CI jobs green on the PR.
- [ ] **Step 4: Commit** with `ci: test CLI, rules, image and dogfood shipguard`.

### Task 22: Release pipeline

**Files:**
- Modify: `.github/workflows/release.yml`
- Create: `scripts/publish-gitlab.sh`, `adapters/gitlab/publish/.gitlab-ci.yml` (the publish project's own pipeline: smoke test using `adapters/gitlab/test/.gitlab-ci.yml`, then a `release:` job on tags that publishes to the Catalog)

- Release jobs after the existing `ci` and `release` (semantic-release) jobs, each gated on `needs.release.outputs.released == 'true'`:
  1. **image:** modelled on shiptag's image job.
     - Tags: `type=semver,pattern=v{{version}}`, `{{version}}`, `v{{major}}.{{minor}}` and `v{{major}}`.
     - `provenance: mode=max`, `sbom: true`, push to GHCR.
     - Then sign with `sigstore/cosign-installer` and `cosign sign --yes ghcr.io/faridlamaul/shipguard@<digest>`.
     - Then run `actions/attest-build-provenance` with `subject-name` and `subject-digest`.
     - Permissions: `packages: write`, `id-token: write`, `attestations: write`.
  2. **gitlab:**
     - `render-gitlab.sh "${VERSION}" dist/gitlab`.
     - `publish-gitlab.sh` clones `gitlab.com/faridlamaul/shipguard` with the `GITLAB_PUBLISH_TOKEN` secret, replaces `templates/` with `dist/gitlab`, copies `README.md`, `LICENSE` and the publish `.gitlab-ci.yml`, commits with the message `release X.Y.Z`, and tags `X.Y.Z` (no `v`).
     - It verifies the pushed `templates/` byte-for-byte against `dist/gitlab` and fails on any difference.
  3. **major-tag:** copy shiptag's job so `vX` follows the newest stable release.
- The owner must create the gitlab.com project and the `GITLAB_PUBLISH_TOKEN` secret (project access token, `write_repository`) before the first release.

- [ ] **Step 1: Implement**, then run `actionlint` and `zizmor`. Expected: clean.
- [ ] **Step 2: Dry-run `publish-gitlab.sh`** against a scratch gitlab.com project with `VERSION=0.0.0-test`. Expected: a tag `0.0.0-test` with rendered templates and a passing smoke test in that project.
- [ ] **Step 3: Commit** with `ci(release): publish signed image and GitLab catalog component`.

### Task 23: Documentation and examples

**Files:**
- Modify: `README.md`
  - Rewrite around shipguard.
  - Keep the existing reusable-workflow section under "Legacy workflows" with its examples corrected to `@v1.0.3`. The floating `v1` tag starts with the first shipguard release.
- Create:
  - `docs/github.md`, `docs/gitlab.md`, `docs/bitbucket.md`: usage, inputs, permissions, hardening (SHA and digest pinning, `cosign verify` command), tier notes
  - `docs/configuration.md`: every `.shipguard.yaml` key, the default policy, exceptions, PR base-policy behaviour, CODEOWNERS recommendation, air-gapped variables (`SHIPGUARD_TRIVY_DB_REPOSITORY`, `SHIPGUARD_OSV_OFFLINE_DB`)
  - `examples/github/security.yml`, `examples/gitlab/.gitlab-ci.yml`, `examples/bitbucket/bitbucket-pipelines.yml`: exactly the spec §5.4 snippets
  - `CONTRIBUTING.md`, `SECURITY.md`: adapted from shiptag

- [ ] **Step 1: Write the docs.** `examples/*` must match spec §5.4 byte-for-byte in their YAML bodies.
- [ ] **Step 2: Check every `.shipguard.yaml` snippet in the docs** with `shipguard gate --config <snippet>` against an empty `findings.json`, scripted in `make docs-check`. Expected: exit 0 for all snippets.
- [ ] **Step 3: Commit** with `docs: document shipguard usage on GitHub, GitLab and Bitbucket`.
