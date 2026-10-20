# shipguard: cross-platform security scanning (sub-project #1)

- **Status:** draft, awaiting owner review
- **Date:** 2026-10-20
- **Scope:** sub-project #1 of the shipguard DevSecOps roadmap

## 1. Goal

shipguard is a DevSecOps CI/CD template for open-source projects, companies and individuals. A consumer calls it from their own CI on **GitHub Actions, GitLab CI or Bitbucket Pipelines** and gets the same security scanning, the same policy decision and the same reports on all three.

### Success criteria

- A consumer adds one job or step (about 5 to 15 lines of YAML) on any of the three platforms and gets secrets, SAST, SCA and IaC scanning with a policy gate.
- The same commit scanned with the same shipguard version and config gives the same findings and the same pass/fail decision on every platform.
- Findings appear in the platform's native security UI where one exists (GitHub Code Scanning via SARIF, GitLab security report artifacts, Bitbucket Code Insights), plus a Markdown summary everywhere.
- A failure of shipguard itself is never reported as a pass.

### Roadmap (each sub-project gets its own spec, plan and implementation)

1. **Cross-platform core and security scanning (this spec).**
2. Build and test per language (Go, Node, Python, Ruby, Rust), including the fixes the audit found in the existing `go-ci`, `node-ci` and `python-ci` workflows.
3. Supply chain and release for consumer artifacts: image build and scan, SBOM, signing and attestation, semantic release through shiptag, GoReleaser.
4. Deploy hooks (GitOps trigger, environment promotion).

### Out of scope for #1

- Language build, lint and test jobs (#2).
- Building, scanning or signing the consumer's own images, and application SBOMs (#3).
- Deployment (#4).
- Changes to the existing reusable workflows (`go-ci.yml`, `node-ci.yml`, `python-ci.yml`, `docker-build.yml`, `go-release.yml`, `semantic-release.yml`). They keep working for current consumers such as `omp-cost`.

## 2. Decisions

| Topic | Decision | Main reason |
|---|---|---|
| Execution model | One `shipguard` container image holding a Go CLI and pinned scanners; adapters only call the CLI | Guarantees parity across platforms; a Bitbucket pipe must be an image anyway |
| SAST engine and rules | opengrep (LGPL-2.1) with a shipguard-curated MIT ruleset, plus consumer rules | Semgrep registry rules (Semgrep Rules License v1.0) may not be redistributed; `opengrep-rules` is archived with an unclear license |
| Default policy | Enforce with practical thresholds, exceptions with mandatory expiry, `audit` mode for onboarding | Every failure is actionable; exceptions cannot be forgotten |
| GitLab distribution | Source in `adapters/gitlab/`, used via `include: remote` and published as a CI/CD Catalog component to a generated gitlab.com project | Works on self-managed GitLab and on gitlab.com Catalog |
| Repository layout | Platform logic in `adapters/{github,gitlab,bitbucket}`; `.github/workflows/` holds only thin wrappers, as GitHub requires | Consistent layout; GitHub only loads reusable workflows from `.github/workflows/` with no subdirectories |
| Versioning | Git tags stay `vX.Y.Z`; the GitLab Catalog project is tagged `X.Y.Z` | Owner preference; GitLab Catalog requires a 3-digit semver tag without a prefix |

## 3. Architecture

### 3.1 Repository layout

```
shipguard/
├── cmd/shipguard/          # CLI entrypoint
├── internal/
│   ├── scanner/            # one runner per scanner: gitleaks, opengrep, osv-scanner, trivy
│   ├── finding/            # unified Finding model, normalization, fingerprints, redaction
│   ├── policy/             # .shipguard.yaml loading and validation, thresholds, exceptions
│   ├── report/             # SARIF, GitLab security reports, Bitbucket Code Insights, Markdown summary
│   └── platform/           # detects GitHub/GitLab/Bitbucket and PR/MR context from env
├── rules/                  # curated opengrep ruleset (MIT) with positive and negative tests
├── schema/                 # JSON Schema for .shipguard.yaml and findings.json
├── testdata/fixtures/      # deliberately vulnerable go, node, python, ruby and rust projects
├── Dockerfile              # CLI + scanners pinned by version and SHA-256 checksum
├── versions.env            # scanner versions and checksums (single source of truth)
├── adapters/
│   ├── github/             # composite action
│   ├── gitlab/             # job templates (include: remote; published as Catalog templates/)
│   └── bitbucket/          # pipe.yml metadata and README
├── .github/workflows/      # scan.yml (thin wrapper calling adapters/github) and this repo's CI/release
├── examples/{github,gitlab,bitbucket}/
└── docs/
```

The CLI, image, rules and adapters live in one repository and ship under one release tag, so their versions cannot drift apart.

### 3.2 Data flow

Every platform runs the same three commands inside the image:

```
shipguard scan [secrets|sast|sca|iac|all]  ->  .shipguard/findings.json
shipguard gate                             ->  exit code + .shipguard/summary.md
shipguard report [--format <fmt>]          ->  platform-native report(s)
```

1. **scan** runs the selected scanners. It keeps each scanner's raw output in `.shipguard/raw/` and writes normalized findings to `.shipguard/findings.json`.
2. **gate** applies the effective policy (defaults, then `.shipguard.yaml`, then adapter inputs and CLI flags) and exceptions. It writes the Markdown summary and exits with the code in §6.1.
`shipguard run` runs all three in order, always attempts `report`, and returns the gate's exit code. Adapters call only `run` (§12 A3).

3. **report** detects the platform from env (`GITHUB_ACTIONS`, `GITLAB_CI`, `BITBUCKET_BUILD_NUMBER`) and writes the native format. `--format` overrides the detection.

| Platform | Native output |
|---|---|
| GitHub | SARIF 2.1.0 uploaded to Code Scanning; summary written to the job summary |
| GitLab | `sast`, `dependency_scanning` and `secret_detection` report artifacts; summary in the job log |
| Bitbucket | Code Insights report and annotations; summary in the step log |

### 3.3 Finding model

Each finding has:
- `id` (rule id, CVE or GHSA)
- `scanner`
- `category` (`secrets`, `sast`, `sca`, `iac`)
- `severity`, normalized to `critical | high | medium | low | info`
- `file` and `line`
- `fix_available` (SCA)
- `fingerprint`
- `status` (`new` or `existing`, PR/MR only)
- `message`

Normalization rules:
- **Severity:** opengrep `ERROR`, `WARNING` and `INFO` map to `high`, `medium` and `low`. Scanners that already use CVSS-style levels keep them.
- **Fingerprint:** a hash of the rule id, file path and normalized code snippet, without the line number, so findings stay stable when code moves.
- **Redaction:** secret values are removed during normalization. They never reach `findings.json`, logs, summaries or reports.

## 4. Scanners and coverage

| Category | Tool | Target |
|---|---|---|
| `secrets` | gitleaks | file contents, plus git history per context (§4.2) |
| `sast` | opengrep + `rules/` + consumer rules | source code |
| `sca` | osv-scanner (vulnerabilities), `trivy fs --scanners license` (licenses) | lockfiles and manifests |
| `iac` | trivy `config` | Dockerfile, Kubernetes YAML, Helm, Terraform, CloudFormation, Compose |

hadolint is not included. trivy covers Dockerfile security, and Dockerfile lint quality belongs to sub-project #2.

License findings are report-only unless the consumer sets `scanners.sca.licenses.deny`.

### 4.1 Language coverage

| | Go | Node | Python | Ruby | Rust |
|---|---|---|---|---|---|
| SCA inputs | `go.mod` | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` (verification item V4) | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements*.txt` | `Gemfile.lock` | `Cargo.lock` |
| SAST rules v1 | yes | yes (JS/TS) | yes | yes | yes |

Secrets and IaC scanning do not depend on the language.

The initial curated SAST ruleset covers, for each language where it applies:
- command and SQL injection
- path traversal
- SSRF
- unsafe deserialization
- weak crypto and hashing
- disabled TLS verification
- hard-coded credentials
- `eval` and unsafe code

Every rule must have positive and negative test cases that pass `opengrep --test`.

### 4.2 Diff-aware scanning

| Context | What is scanned | What fails the gate |
|---|---|---|
| PR / MR | head and base ref | only findings whose fingerprint is not in the base scan (`new`); `existing` findings are reported but do not fail |
| Push to default branch, tag | full tree | every finding above threshold |
| Scheduled | full tree, plus full git history for secrets | every finding above threshold (this catches new CVEs in old dependencies) |

**How diff-awareness works:**
- For SAST, SCA and IaC, shipguard scans the base ref in a `git worktree` and compares fingerprints with the head scan.
- For secrets, shipguard scans the commit range `base..head` with gitleaks, which only returns new findings by construction.

**Base ref detection:**

| Platform | PR/MR signal | Base |
|---|---|---|
| GitHub | `GITHUB_EVENT_NAME=pull_request` | `GITHUB_BASE_REF` |
| GitLab | `CI_PIPELINE_SOURCE=merge_request_event` | `CI_MERGE_REQUEST_DIFF_BASE_SHA` |
| Bitbucket | `BITBUCKET_PR_ID` set | `BITBUCKET_PR_DESTINATION_BRANCH` |

**History depth:** adapters fetch enough history themselves, so consumers configure nothing.
- GitHub: `fetch-depth: 0`.
- GitLab: `GIT_DEPTH: 0`.
- Bitbucket: the pipe runs `git fetch --unshallow` when the clone is shallow (verification item V2). If V2 fails, the docs require `clone: depth: full`, and shipguard exits with code 2 and a clear message when history is missing. It never scans the wrong range silently.

### 4.3 Vulnerability databases

osv-scanner queries the OSV database at runtime, and trivy fetches its misconfiguration checks bundle at runtime; neither is baked into the image, so they never go stale. Adapters cache them with each platform's cache mechanism (see §12 A6).

For mirrors and air-gapped environments:
- `SHIPGUARD_TRIVY_CHECKS_BUNDLE_REPOSITORY` points trivy at a checks-bundle mirror.
- osv-scanner offline mode reads a local database path.

## 5. Configuration and adapter interface

### 5.1 Precedence

Built-in defaults, then `.shipguard.yaml`, then adapter inputs and CLI flags. When `.shipguard.yaml` is missing, the defaults apply.

### 5.2 `.shipguard.yaml`

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/faridlamaul/shipguard/v1.0.0/schema/shipguard.schema.json
version: 1
mode: enforce                    # enforce | audit

paths:
  exclude: ["vendor/", "**/testdata/**"]   # node_modules, .git etc. are excluded by default

scanners:
  secrets: { enabled: true }
  sast:
    enabled: true
    rules: ["./.shipguard/rules/"]         # extra consumer rules: paths or URLs
    disable_rules: ["shipguard.go.weak-hash"]
    default_excludes: true                 # skip vendor/, build/, dist/, test/, tests/, *_test.go, *.min.js ... (see A7)
  sca:
    enabled: true
    licenses: { deny: [] }                 # e.g. [AGPL-3.0]
  iac: { enabled: true }

timeouts:
  per_scanner: 15m

policy:                                    # unified severities: critical|high|medium|low
  fail_on:
    secrets: any
    sast: high
    sca: { severity: high, fix_available_only: true }
    iac: high

exceptions:
  - id: CVE-2026-1234                      # CVE/GHSA, rule id or fingerprint
    path: "go.sum"                         # optional, narrows the match
    reason: "Not reachable; waiting for upstream v2.3"
    expires: 2026-12-31                    # required
```

The defaults are the values shown above. **Default policy:** fail on any secret, on high or critical SAST findings, on high or critical SCA vulnerabilities that have a fixed version, and on high or critical IaC findings. Unfixed vulnerabilities are reported, not failed.

**Validation:**
- Unknown keys are errors (exit 2).
- An exception without `reason` or `expires` is an error.
- An expired exception no longer suppresses its finding.
- The JSON Schema is published in `schema/`.

**PR/MR protection:**
- On a PR/MR, the policy is read from the **base ref**, so a PR cannot weaken its own gate.
- When the PR/MR changes `.shipguard.yaml`, the summary shows a "policy changed in this PR" warning with the diff.
- The docs recommend protecting the file with CODEOWNERS.

### 5.3 Adapter inputs

Policy lives only in `.shipguard.yaml`. Adapters expose only these inputs.

| Concept | GitHub `with:` | GitLab `inputs:` | Bitbucket `variables:` | Default |
|---|---|---|---|---|
| scanners to run | `scanners` | `scanners` | `SCANNERS` | `all` |
| mode override | `mode` | `mode` | `MODE` | from config |
| config path | `config` | `config` | `CONFIG` | `.shipguard.yaml` |
| image override | `image` | `image` | (the pipe is the image) | release digest |
| native report upload | `upload_sarif` (`auto`, `true` or `false`) | always (artifacts) | `CODE_INSIGHTS` | `auto` / `true` |

**Outputs:**
- `result` (`pass`, `fail` or `audit`), `new_findings` and `total_findings`.
- The `.shipguard/` directory, uploaded as an artifact.

**Platform notes:**
- **GitHub:** SARIF upload needs `security-events: write`. Private repositories without GitHub Advanced Security have no Code Scanning, so with `upload_sarif: auto` a refused upload is a warning.
- **GitLab:** security dashboards and MR widgets need the Ultimate tier. On other tiers the artifacts are still produced and the summary is in the job log.
- **Bitbucket:** Code Insights is posted through the Pipelines proxy at `localhost:29418` without a token (verification item V3).

### 5.4 Consumer usage

```yaml
# GitHub: .github/workflows/security.yml
jobs:
  security:
    uses: faridlamaul/shipguard/.github/workflows/scan.yml@v1.0.0
    permissions: { contents: read, security-events: write, actions: read }
    with:
      scanners: all
      mode: enforce
      config: .shipguard.yaml
```

```yaml
# GitLab: .gitlab-ci.yml
include:
  - component: gitlab.com/faridlamaul/shipguard/scan@1.0.0
    inputs:
      scanners: all
      mode: enforce
      config: .shipguard.yaml
# Self-managed GitLab:
#  - remote: https://gitlab.com/faridlamaul/shipguard/-/raw/1.0.0/templates/scan.yml   (see §12 A2)
#    integrity: sha256-<published hash>
#    inputs: { scanners: all, mode: enforce, config: .shipguard.yaml }
```

```yaml
# Bitbucket: bitbucket-pipelines.yml
- step:
    name: security
    script:
      - pipe: docker://ghcr.io/faridlamaul/shipguard:v1.0.0
        variables:
          SCANNERS: all
          MODE: enforce
          CONFIG: .shipguard.yaml
```

The docs describe hardening options: pinning the GitHub reference to a commit SHA, and pinning the pipe or image to a digest.

## 6. Error handling

### 6.1 Exit codes

| Code | Meaning |
|---|---|
| 0 | pass, or `audit` mode with findings |
| 1 | policy failure (findings above threshold) |
| 2 | tool or configuration error |

### 6.2 Rules

- **Fail closed.**
  - A scanner crash, timeout, missing git history or invalid config exits with 2, in `audit` mode as well.
  - A scan that did not run never counts as clean.
- **Database downloads** are retried 3 times with backoff before exiting with 2.
- **Report upload failures** (no Code Scanning, Code Insights API error) are warnings. They do not change the gate result, and the summary is still printed.
- **Secrets** are redacted in every output (§3.3).

## 7. Supply chain of shipguard itself

### 7.1 Image

- Multi-stage build.
- Minimal base image pinned by digest.
- Each scanner binary is verified against the SHA-256 checksum in `versions.env`.
- Runs as root inside the container (see §12 A1).
- Built for `linux/amd64` and `linux/arm64`.

### 7.2 Release signing

- The image is signed with cosign keyless (GitHub OIDC).
- SLSA build provenance comes from `actions/attest-build-provenance`.
- The image SBOM is attached as an attestation.
- The docs show `cosign verify` for consumers.

### 7.3 This repository's CI

- shipguard scans itself (dogfooding).
- Workflows are checked with zizmor and actionlint.
- Every workflow uses `persist-credentials: false`, passes inputs through `env:` rather than `${{ }}` in `run:`, and declares minimal `permissions`.

### 7.4 Updates

- Dependabot covers GitHub Actions, `go.mod` and the base image.
- A scheduled `bump-scanners` workflow checks upstream releases, updates `versions.env` versions and checksums, and opens a PR. The full test suite must pass before it can merge.

## 8. Testing

| Layer | Content |
|---|---|
| Unit (Go) | per-scanner normalization against golden files of real scanner output; policy engine (thresholds, expiry, base-ref policy, validation errors); fingerprint stability under line shifts; secret redaction |
| Format validation | SARIF output against the SARIF 2.1.0 schema; GitLab reports against the official GitLab security report schemas |
| Rules | `opengrep --test` for every rule in `rules/` |
| Image E2E | the built image runs against `testdata/fixtures/{go,node,python,ruby,rust}` with expected findings, including a two-commit PR scenario that checks `new` versus `existing` |
| GitHub adapter | this repository calls its own `scan.yml` against a fixture |
| GitLab adapter | the generated gitlab.com project runs a smoke test before its Catalog release |
| Bitbucket adapter | a test repository in a Bitbucket workspace runs the pipe for each release candidate |

## 9. Versioning and release

**Semver contract:**
- adapter inputs and outputs
- the `.shipguard.yaml` schema (`version: 1`)
- CLI exit codes
- the `findings.json` schema

Breaking any of them requires a major release.

**Release flow (on push to `main`):**
1. shiptag creates `vX.Y.Z` (`v_prefix` stays enabled).
2. The multi-arch image is built and pushed to `ghcr.io/faridlamaul/shipguard` as `vX.Y.Z` and `X.Y.Z`.
3. The image is signed and attested, and the GitHub Release is published.
4. `adapters/gitlab/*` is copied to `templates/` in the gitlab.com project `faridlamaul/shipguard` together with `README.md` and `LICENSE`, and tagged `X.Y.Z`. That project's `release:` job publishes it to the CI/CD Catalog.
5. CI checks that the published `templates/` files are byte-identical to `adapters/gitlab/` at the same tag.

**Floating major references:**
- GitHub and the image get a floating `v1` tag. This also fixes the audit finding that the README uses a `@v1` tag that does not exist.
- GitLab users can use the partial version `@1`.
- The docs still recommend full versions, SHAs or digests.

## 10. Verification items (spike before adapter work)

| # | Question | Fallback if it fails |
|---|---|---|
| V1 | Can a Bitbucket pipe use a GHCR image, and can it be pinned by digest? | Also publish the image to Docker Hub; document tag pinning |
| V2 | Does `git fetch --unshallow` work inside a Bitbucket pipe? | Document `clone: depth: full`; exit 2 when history is missing |
| V3 | Can a pipe post Code Insights through the `localhost:29418` proxy? | Accept an app password or access token variable; otherwise summary only |
| V4 | Does osv-scanner support `bun.lock`? | Document as unsupported until upstream adds it |
| V5 | Are opengrep binaries available for linux/arm64? | Ship amd64 only for the first release |
| V6 | Does `include: remote` from raw.githubusercontent work with `inputs` and `integrity`? | Self-managed users mirror the published gitlab.com project and use `include: project` |

## 11. References

- GitHub, reusable workflows (location must be `.github/workflows`, no subdirectories): https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows
- GitLab CI/CD components (`templates/` layout, semantic version tags): https://docs.gitlab.com/ci/components/
- GitLab `include:remote` and `include:integrity`: https://docs.gitlab.com/ci/yaml/
- Bitbucket custom pipes: https://support.atlassian.com/bitbucket-cloud/docs/write-a-pipe-for-bitbucket-pipelines/
- Semgrep Rules License: https://semgrep.dev/legal/rules-license
- Opengrep: https://github.com/opengrep/opengrep

## 12. Amendments (found while writing the implementation plan)

**A1. The image runs as root.**
- GitLab job images and Bitbucket pipes write into root-owned clone directories, and GitHub Docker steps need workspace access. shiptag runs as root for the same reason.
- Isolation comes from the container.
- Replaces the earlier "non-root" requirement in §7.1.

**A2. Rendered GitLab templates.**
- `adapters/gitlab/` contains a single placeholder `__SHIPGUARD_VERSION__` for the default image tag.
- At release it is rendered with the version and published to the gitlab.com project.
- Both the Catalog component and `include: remote` read the rendered file from that project, with the remote URL `https://gitlab.com/faridlamaul/shipguard/-/raw/X.Y.Z/templates/scan.yml`. The two paths therefore get byte-identical content with a correct image tag.
- The earlier raw.githubusercontent URL could not carry its own version.

**A3. `shipguard run`.**
- A convenience command that runs scan, gate and report.
- Adapters call only this command, so they stay free of logic.

**A4. Bitbucket schedules.**
- Bitbucket exposes no variable for scheduled runs.
- `SHIPGUARD_EVENT=schedule` (any platform) overrides the detected event, and the Bitbucket docs tell scheduled custom pipelines to set it.

**A5. The GitHub adapters resolve their own version.**
- **The composite action** uses `ghcr.io/faridlamaul/shipguard:<action_ref>` when its ref is a version tag, and builds the image from its own source when pinned by SHA. Pinning by SHA is therefore exact but slower; the `image` input can point at a digest instead.
- **The reusable workflow** needs its own SHA to check out `adapters/github`. Learning that SHA is verification item **V7**:
  - Try the `job.workflow_sha` context.
  - Fallback: the OIDC `job_workflow_sha` claim, which requires the caller to grant `id-token: write`.

| # | Question | Fallback if it fails |
|---|---|---|
| V7 | Can a called reusable workflow read its own commit SHA? | OIDC `job_workflow_sha` claim; callers add `id-token: write` |

**A6. Decisions made during implementation (Tasks 1–17).**
- **trivy:** config and license scans (trivy 0.76) do not use the vulnerability DB. The DB download was dropped. `trivy config` is retried 3 times because it fetches the checks bundle, and mirrors use `SHIPGUARD_TRIVY_CHECKS_BUNDLE_REPOSITORY`.
- **Raw output:** every scanner writes its tool output to a temp file outside the repo. `.shipguard/raw/<tool>.json` holds only the normalized findings, so no source lines or secrets are kept.
- **License deny:** entries match the whole license family. `GPL-3.0` also matches `GPL-3.0-only`, `GPL-3.0-or-later` and `GPL-3.0+`.
- **Gate fails closed (exit 2)** in two cases:
  - on a PR without `.shipguard/policy.yaml`;
  - when no scanner ran.
- **PR diff:** fingerprints are matched as a multiset, so a second identical vulnerable snippet counts as new.
- **opengrep rule ids:** the config-directory prefix that opengrep adds is stripped, and `disable_rules` takes bare rule ids.

**A7. Policy lives only in `.shipguard.yaml` (ruling R-C2).**
- The only policy is `.shipguard.yaml`, read from the base ref on a PR/MR. Exceptions go there, with `reason` and `expires`.
- On every event, not only on PRs, the built-in scanners ignore the scanner-native config files, ignore files and inline suppressions that a repository can contain:

| Scanner | Neutralized | How (pinned version) |
|---|---|---|
| gitleaks 8.30.1 | `.gitleaks.toml`, `GITLEAKS_CONFIG*`, `.gitleaksignore`, `gitleaks:allow` | `--config` with a defaults-only file (`[extend] useDefault = true`), `--gitleaks-ignore-path` set to an empty temp dir, and `--ignore-gitleaks-allow`. gitleaks always loads `<source>/.gitleaksignore`, so history scans pass the git dir as the source, and directory scans go through a random temp symlink to the work tree, whose path prefix no committed fingerprint can match. |
| opengrep 1.31.0 | `nosem`, `nosemgrep` and `noopengrep` comments, `.semgrepignore` | `--disable-nosem` and `--x-ignore-semgrepignore-files`. This also drops opengrep's built-in default ignore list, which `scanners.sast.default_excludes` restores (see below). `paths.exclude` and shipguard's built-in excludes are passed as `--exclude`. `.gitignore` cannot hide tracked files. |
| trivy 0.76.0 | `trivy.yaml`, `.trivyignore` | `--config ""` and `--ignorefile ""` on both the config and the license scans; trivy documents the empty value as "disables loading". |
| osv-scanner 2.7.0 | `osv-scanner.toml`, `.gitignore` hiding lockfiles | `--config` with an empty file, which overrides every per-directory config, and `--no-ignore`. Directory-shaped excludes (`vendor/`, `**/testdata/**`, the built-in ones) are passed as `--x-exclude`, so osv-scanner does not walk them. Only `dir/` and `**/name/**` entries can be honoured this way; other globs only filter findings. Any extraction error on osv-scanner's stderr fails the scan, because the paths it prints are repository-controlled. |

- **SAST default excludes:** `scanners.sast.default_excludes` (bool, default `true`). When true, shipguard passes this fixed list to opengrep as `--exclude`: `vendor/`, `build/`, `dist/`, `node_modules/`, `.venv/`, `.env/`, `.tox/`, `.npm/`, `.yarn/`, `_build/`, `.hg/`, `.svn/`, `CVS/`, `_darcs/`, `test/`, `tests/`, `*_test.go` and `*.min.js`. It mirrors opengrep 1.31.0's built-in defaults, observed by scanning a tree with and without `--x-ignore-semgrepignore-files`. The list is defined in code, not by the repository, and on a PR the policy comes from the base, so a PR cannot turn it off for itself. Set it to `false` to scan those paths.
- **Consumer rules:** relative `scanners.sast.rules` paths, and absolute ones inside the repository, resolve in the base worktree on a PR, never in the PR head. A local rule path that does not exist is a config error (exit 2).
- **Known gaps:**
  - trivy 0.76 has no switch to disable inline `trivy:ignore:<id>` comments in IaC files, so they still apply.
  - gitleaks' built-in default config has a global path allowlist, for example `node_modules/`, lockfiles and `vendor/modules.txt`. It is not repository-controlled, and it still applies.
- **Related rulings:**
  - **R-C1.** A denied license blocks regardless of `fix_available_only`, because licenses have no fix. The severity threshold still applies.
  - **R-I3.** shipguard's built-in excludes never hide a committed secret. A history scan (PR or schedule) applies only `paths.exclude`. A directory scan also skips shipguard's run-time files: its outputs in `.shipguard/`, `.shipguard-cache/` and `.shipguard-action/`.
