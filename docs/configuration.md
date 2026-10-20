# Configuration

shipguard reads one policy file, `.shipguard.yaml`, from the repository root. If the file is missing, the built-in defaults apply. The JSON Schema is in [`schema/shipguard.schema.json`](../schema/shipguard.schema.json); add this line to the top of your file for editor completion:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/faridlamaul/shipguard/main/schema/shipguard.schema.json
```

Precedence, lowest to highest: built-in defaults, `.shipguard.yaml`, then adapter inputs and CLI flags (`--mode` and friends).

Unknown keys are errors (exit code 2). Every snippet on this page marked as a config is checked against the real CLI by `make docs-check`.

## The defaults

This is the whole default policy. A file that sets none of these keys behaves the same way:

```yaml shipguard-config
version: 1
mode: enforce

paths:
  exclude: []

scanners:
  secrets: { enabled: true }
  sast:
    enabled: true
    rules: []
    disable_rules: []
    default_excludes: true
  sca:
    enabled: true
    licenses: { deny: [] }
  iac: { enabled: true }

timeouts:
  per_scanner: 15m

policy:
  fail_on:
    secrets: any
    sast: high
    sca: { severity: high, fix_available_only: true }
    iac: high

exceptions: []
```

In words: fail on any secret, on high or critical SAST findings, on high or critical IaC findings, and on high or critical SCA vulnerabilities that have a fixed version. Unfixed vulnerabilities are reported but do not fail the gate. Licenses are report-only until you set `scanners.sca.licenses.deny`.

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | `1` | Must be `1`. |
| `mode` | `enforce` or `audit` | `enforce` | `audit` reports findings and exits 0 (see [exit codes](#exit-codes)). |
| `paths.exclude` | list of globs | `[]` | Paths no scanner reports on. See [Excluding paths](#excluding-paths). |
| `scanners.secrets.enabled` | bool | `true` | gitleaks. |
| `scanners.sast.enabled` | bool | `true` | opengrep with the rules in `rules/` plus yours. |
| `scanners.sast.rules` | list of strings | `[]` | Extra opengrep rules: local paths or URLs. A local path that does not exist is a config error. |
| `scanners.sast.disable_rules` | list of strings | `[]` | Full rule ids to switch off, for example `shipguard.rust.weak-hash`. |
| `scanners.sast.default_excludes` | bool | `true` | Skip opengrep's usual non-product paths. See [SAST default excludes](#sast-default-excludes). |
| `scanners.sca.enabled` | bool | `true` | osv-scanner for vulnerabilities, trivy for licenses. |
| `scanners.sca.licenses.deny` | list of strings | `[]` | SPDX license names to block. Matches the whole family. |
| `scanners.iac.enabled` | bool | `true` | trivy config scan. |
| `timeouts.per_scanner` | duration string | `15m` | A duration string such as `15m` or `1h`; a bare number is an error. |
| `policy.fail_on.<category>` | threshold | see above | Categories: `secrets`, `sast`, `sca`, `iac`. Must not be empty. |
| `exceptions` | list | `[]` | See [Exceptions](#exceptions). |

A threshold is one of:

- `any`: every finding of that category fails.
- a severity (`critical`, `high`, `medium`, `low`, `info`): findings at or above it fail.
- `{ severity: high, fix_available_only: true }`: as above, but only findings that have a fixed version fail. A denied license still fails, because licenses have no fix.

`disable_rules` takes the full rule id as it appears in the findings (`shipguard.<language>.<rule>` for the built-in rules). "Bare" only means without the directory prefix opengrep adds when it loads a rules directory. A short name such as `weak-hash` matches nothing and silently does nothing.

Local rules (`scanners.sast.rules`) and rule files are resolved in the base ref on a pull request, never in the PR head.

## Exceptions

```yaml shipguard-config
exceptions:
  - id: CVE-2026-1234          # CVE or GHSA id, rule id, or finding fingerprint
    path: "go.sum"             # optional; exact path or glob that narrows the match
    reason: "Not reachable; waiting for upstream v2.3"
    expires: 2026-12-31        # required, YYYY-MM-DD
```

- `id`, `reason` and `expires` are required. A missing field is a config error.
- `expires` is a date in `YYYY-MM-DD` form. The exception stays active through the end of that day (UTC) and stops suppressing the next day. An expired exception that matched a finding is listed in the summary; one that matches nothing is not reported.
- License findings have the id `license:<SPDX>`, for example `license:AGPL-3.0`. Use that as the exception `id`.
- Findings suppressed by an exception are left out of SARIF, GitLab and Bitbucket reports; they remain in .shipguard/findings.json and the summary.
- This file is the only place to suppress a finding. Scanner ignore files and inline comments are ignored (see [Scanner-native config is ignored](#scanner-native-config-is-ignored)).

## Denying licenses

`scanners.sca.licenses.deny` matches the whole license family. `GPL-3.0` also matches `GPL-3.0-only`, `GPL-3.0-or-later` and `GPL-3.0+`.

```yaml shipguard-config
scanners:
  sca:
    licenses:
      deny: [AGPL-3.0, GPL-3.0]
```

A denied license fails the gate whatever `fix_available_only` says, but the SCA severity threshold still applies.

## Excluding paths

```yaml shipguard-config
paths:
  exclude:
    - vendor/
    - "**/testdata/**"
```

- `.git/` and `node_modules/` are always excluded from SAST, SCA and IaC. shipguard's own run-time output is never scanned in a directory scan: `.shipguard/findings.json`, `policy.yaml`, `raw/`, `summary.md`, `gate.env`, `*.sarif` and `gl-*.json`, plus `.shipguard-cache/` and `.shipguard-action/`. Other files in `.shipguard/` (your consumer rules) are scanned.
- Secrets scanning applies only `paths.exclude`, so a committed secret is never hidden by a built-in exclude. A history scan (PR or scheduled) reads committed content only, so it sees committed files anywhere, including under those run-time paths.
- osv-scanner can skip a directory while it walks the tree only for the forms `dir/` and `**/name/**`. Other globs only filter the findings after the walk.
- That has a consequence: a corrupt lockfile in a path that is not excluded in one of those two forms fails the SCA scan (exit 2). If you have a fixture with a broken lockfile, exclude it as `dir/` or `**/name/**`.

### SAST default excludes

With `scanners.sast.default_excludes: true` (the default), SAST skips this fixed list: `vendor/`, `build/`, `dist/`, `node_modules/`, `.venv/`, `.env/`, `.tox/`, `.npm/`, `.yarn/`, `_build/`, `.hg/`, `.svn/`, `CVS/`, `_darcs/`, `test/`, `tests/`, `*_test.go` and `*.min.js`. The list mirrors opengrep's own defaults and lives in shipguard, not in your repository. Set it to `false` to scan those paths too:

```yaml shipguard-config
scanners:
  sast:
    default_excludes: false
```

## Pull requests: the policy comes from the base

On a pull request or merge request:

- shipguard reads `.shipguard.yaml` from the **base ref**, not from the PR head, so a PR cannot weaken its own gate. The same goes for local SAST rule paths.
- If the PR changes the file, the summary shows a "Policy changed in this PR" warning with the diff.
- Only findings that are new relative to the base can fail the gate. Findings that already exist are reported but do not fail it.
- If the base has no `.shipguard.yaml`, the built-in defaults apply and the summary says so.

What to do about it:

1. **Protect the file with CODEOWNERS**, so a policy change needs an owner's approval:

   ```
   # .github/CODEOWNERS
   /.shipguard.yaml  @your-org/security
   ```

   GitLab and Bitbucket have equivalent code-owner and approval rules.
2. **Bootstrap in its own PR.** The base-ref policy means a PR that adds `.shipguard.yaml` for the first time is still gated by the defaults. Merge the file in its own PR first, then turn enforcement on (for example by switching a required check on).

## Scanner-native config is ignored

On every event, not only on PRs, shipguard neutralizes the configuration, ignore files and inline suppressions that a repository can carry, because a contributor could add them to hide a finding. Put exceptions in `.shipguard.yaml` instead.

| Scanner | Ignored |
|---|---|
| gitleaks | `.gitleaks.toml`, `GITLEAKS_CONFIG*`, `.gitleaksignore`, `gitleaks:allow` comments |
| opengrep | `nosem`, `nosemgrep` and `noopengrep` comments, `.semgrepignore` |
| trivy | `trivy.yaml`, `.trivyignore` |
| osv-scanner | `osv-scanner.toml`, and `.gitignore` rules that hide lockfiles |

`.gitignore` also cannot hide tracked files from opengrep.

Known gaps:

- trivy 0.76 has no switch to disable inline `trivy:ignore:<id>` comments in IaC files, so they still apply.
- gitleaks' built-in default config has a path allowlist (for example `node_modules/`, lockfiles and `vendor/modules.txt`). It is not controlled by your repository, and it still applies.

## Git history

PR and scheduled scans need the full git history. A shallow clone is a config error (exit 2), with one exception: on Bitbucket shipguard runs `git fetch --unshallow` itself.

- GitHub: `fetch-depth: 0` on `actions/checkout` (the reusable workflow already does this).
- GitLab: `GIT_DEPTH: 0`.
- Bitbucket: nothing to set.

Scans of the default branch and of tags scan the full tree. Scheduled scans also scan the full git history for secrets (only secrets use the history). New CVEs in old dependencies are caught because the scheduled run scans the full tree with SCA.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Pass, or `audit` mode with findings. |
| `1` | Policy failure: findings above the threshold in `enforce` mode. |
| `2` | Tool or configuration error. |

shipguard fails closed. Exit code 2 covers an invalid config, a scanner that crashed or timed out, a shallow clone, a missing `findings.json`, and a run in which no scanner completed. It applies in `audit` mode as well, and it takes precedence over 1. A scan that did not run never counts as clean.

Failing to upload a report (no Code Scanning on the repository, a Code Insights API error) is only a warning and does not change the exit code.

## Environment variables

### Flag fallbacks

Every CLI flag can also be set as `SHIPGUARD_<FLAG>`. An explicit flag wins, then `SHIPGUARD_*`, then (Bitbucket only) the bare variable below, then the default.

| Flag | Variable | Notes |
|---|---|---|
| `--dir` | `SHIPGUARD_DIR` | Repository directory. Default: `GITHUB_WORKSPACE`, `CI_PROJECT_DIR` or `BITBUCKET_CLONE_DIR`, else the current directory. |
| `--config` | `SHIPGUARD_CONFIG` | Default `.shipguard.yaml`. |
| `--mode` | `SHIPGUARD_MODE` | `enforce` or `audit`. |
| `--scanners` | `SHIPGUARD_SCANNERS` | `all`, or a comma list of `secrets`, `sast`, `sca`, `iac`. |
| `--format` | `SHIPGUARD_FORMAT` | `report` and `run` only: `sarif`, `gitlab`, `bitbucket` or `none`. Default by platform. |
| `--code-insights` | `SHIPGUARD_CODE_INSIGHTS` | `report` and `run` only: `false` disables Bitbucket Code Insights. |

On Bitbucket (when `BITBUCKET_BUILD_NUMBER` is set) the pipe also accepts the bare variables `SCANNERS`, `MODE`, `CONFIG` and `CODE_INSIGHTS`.

### Other variables

| Variable | Purpose |
|---|---|
| `SHIPGUARD_EVENT` | Overrides the detected event: `pr`, `push`, `tag`, `schedule` or `manual`. Bitbucket exposes no variable for scheduled runs, so set `SHIPGUARD_EVENT=schedule` on scheduled pipelines. |
| `SHIPGUARD_RULES_DIR` | Directory of the built-in SAST rules. Default `/opt/shipguard/rules` in the image. |
| `SHIPGUARD_TRIVY_CHECKS_BUNDLE_REPOSITORY` | Mirror of the trivy checks bundle, for air-gapped runs. |
| `SHIPGUARD_OSV_OFFLINE_DB` | Path to a local OSV database; osv-scanner then runs offline. |
| `SHIPGUARD_BITBUCKET_PROXY` | Proxy used to post Code Insights. Default `http://localhost:29418` (the Pipelines proxy). Set `none` to use no proxy. |
| `SHIPGUARD_BITBUCKET_TOKEN` | Optional Bearer token for Code Insights. When set, the proxy is not used. |

On the GitHub reusable workflow these variables cannot be set: a caller has no way to pass environment variables into the called workflow. Use the composite action instead (see [docs/github.md](github.md#advanced-environment-variables)).

osv-scanner and trivy download their data at run time (the image ships no databases), so a mirror or an offline database is how you run without internet access.

## Outputs

shipguard writes to `.shipguard/` in the repository: `findings.json`, `policy.yaml` (the effective policy), `summary.md`, `gate.env`, and the platform report (`shipguard.sarif`, or the GitLab reports). Secret values are redacted in every output. The gate also exposes `result` (`pass`, `fail` or `audit`), `new_findings` and `total_findings`.
