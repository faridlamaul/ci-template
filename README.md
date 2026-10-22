<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
    <img alt="shipguard" src="docs/assets/logo-light.svg" width="360">
  </picture>
</p>

<p align="center">
  <strong>Security scanning, build and test, and releases for your CI pipeline.</strong><br>
  One image for GitHub, GitLab and Bitbucket.
</p>

<p align="center">
  <a href="https://github.com/faridlamaul/shipguard/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/faridlamaul/shipguard/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/faridlamaul/shipguard/actions/workflows/release.yml"><img alt="Release" src="https://github.com/faridlamaul/shipguard/actions/workflows/release.yml/badge.svg"></a>
  <a href="https://github.com/faridlamaul/shipguard/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/faridlamaul/shipguard?sort=semver"></a>
  <a href="https://golang.org"><img alt="Go Version" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go"></a>
  <a href="https://opensource.org/licenses/MIT"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
</p>

<p align="center">
  <img alt="shipguard scanning a vulnerable Python project and blocking the gate" src="docs/assets/demo.gif" width="800">
</p>

Security scanning with a policy gate (`shipguard scan`), build and test (`shipguard ci`) and releases with a scanned, signed image (`shipguard release`) for your CI pipeline, on **GitHub**, **GitLab** and **Bitbucket**.

shipguard runs four kinds of scan in one container image, applies one policy file to the results, and reports them to the platform you already use:

| Category | Scanner | Looks at |
|---|---|---|
| `secrets` | gitleaks | file contents, and git history on PR and scheduled scans |
| `sast` | opengrep with the curated rules in `rules/` | source code (Go, JS/TS, Python, Ruby, Rust) |
| `sca` | osv-scanner, and trivy for licenses | lockfiles and manifests |
| `iac` | trivy config | Dockerfile, Kubernetes, Helm, Terraform, CloudFormation, Compose |

On a pull request only the findings the PR introduces can fail the gate. On the default branch and on schedules everything above the threshold fails. One file, `.shipguard.yaml`, is the whole policy.

## Status

| Part | State |
|---|---|
| Go CLI (`scan`, `gate`, `report`, `run`) | done |
| `shipguard release`: version, binaries and a scanned, signed image, see [docs/release.md](docs/release.md) | CLI done |
| `shipguard ci`: lint, test and build for Go, Node, Python, Ruby and Rust on GitHub, GitLab and Bitbucket | done, see [docs/ci.md](docs/ci.md) |
| GitHub adapter (reusable workflow and composite action) | done |
| GitLab component (CI/CD Catalog) | released |
| Bitbucket pipe | released |
| Image `ghcr.io/faridlamaul/shipguard` (signed, with provenance) | released |

The docs write `vX.Y.Z` for the release you pin (GitLab: `X.Y.Z`, no `v`). See [Releases](https://github.com/faridlamaul/shipguard/releases) for the latest version.

## Quick start (GitHub)

Add `.github/workflows/security.yml`:

```yaml
name: Security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 3 * * 1"

jobs:
  security:
    uses: faridlamaul/shipguard/.github/workflows/scan.yml@vX.Y.Z
    permissions: { contents: read, security-events: write, actions: read }
    with:
      scanners: all
      mode: enforce
      config: .shipguard.yaml
```

The defaults need no config file. To change them, add a `.shipguard.yaml` (in its own pull request first; see [Configuration](docs/configuration.md#pull-requests-the-policy-comes-from-the-base)):

```yaml shipguard-config
version: 1
mode: enforce
paths:
  exclude: ["vendor/", "**/testdata/**"]
exceptions:
  - id: CVE-2026-1234
    reason: "Not reachable; waiting for upstream v2.3"
    expires: 2026-12-31
```

## Quick start: lint, test and build (`shipguard ci`)

`shipguard ci` detects the language (Go, Node, Python, Ruby, Rust) and runs pinned lint, test and build steps. Add `.github/workflows/ci.yml`:

```yaml
name: CI
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  ci:
    uses: faridlamaul/shipguard/.github/workflows/build-test.yml@vX.Y.Z
```

GitLab and Bitbucket snippets, the defaults per language, the `ci:` config, outputs and exit codes are in [docs/ci.md](docs/ci.md). This replaces the legacy `go-ci`, `node-ci` and `python-ci` workflows below.

## Screenshots

A pull request whose scan blocks: the job summary lists every blocking finding.

<img alt="shipguard job summary on GitHub listing blocking findings" src="docs/assets/github-job-summary.png" width="800">

A release from `release-artifacts.yml`: the version, the binaries and the signed image with its digest.

<img alt="shipguard release job summary on GitHub" src="docs/assets/github-release-summary.png" width="800">

## Documentation

| Page | Contents |
|---|---|
| [docs/ci.md](docs/ci.md) | `shipguard ci`: usage per platform, defaults per language, `ci:` config, outputs, exit codes, security |
| [docs/release.md](docs/release.md) | `shipguard release`: steps, `release:` config, dry run, outputs, exit codes, verifying releases |
| [docs/configuration.md](docs/configuration.md) | Every `.shipguard.yaml` key, defaults, exceptions, PR policy, ignored scanner config, exit codes, environment variables |
| [docs/github.md](docs/github.md) | Inputs, permissions, hardening, tier notes |
| [docs/gitlab.md](docs/gitlab.md) | Component inputs, `include: remote` with integrity, hardening |
| [docs/bitbucket.md](docs/bitbucket.md) | Pipe variables, schedules, Code Insights, hardening |
| [examples/](examples/) | Ready-to-copy pipeline files |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Pass, or `audit` mode with findings |
| `1` | Policy failure: findings above the threshold |
| `2` | Tool or configuration error (shipguard fails closed) |

## How it protects the gate

- On a PR the policy is read from the **base** branch, so a PR cannot weaken its own gate. The summary warns when the PR changes `.shipguard.yaml`.
- Scanner ignore files, config files and inline suppressions (`.gitleaksignore`, `nosemgrep`, `.trivyignore` and so on) are ignored. Exceptions live in `.shipguard.yaml`, with a reason and an expiry date.
- Secret values are redacted in every output.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

---

## Legacy workflows

This repository also still publishes the reusable GitHub Actions workflows (`workflow_call`) it started with. They are separate from shipguard. `go-ci`, `node-ci` and `python-ci` are deprecated in favour of `shipguard ci` ([docs/ci.md](docs/ci.md)) and will be removed in the next major release. The examples use `@v1.0.3`, the latest published tag. A floating `v1` tag does not exist yet; it starts with the first shipguard release.

Instead of duplicating hundreds of lines of CI/CD YAML across every repository, consume these modular workflows with just a few lines of configuration.

### 📦 Available Reusable Workflows

| Workflow | Path | Description |
|---|---|---|
| **Semantic Release** | `.github/workflows/semantic-release.yml` | Automated Conventional Commits semver bumping, changelog generation, git tagging, and GitHub Releases via the [`shiptag`](https://github.com/faridlamaul/shiptag) container image from GHCR (zero Go setup required). |
| **Go CI** | `.github/workflows/go-ci.yml` | Comprehensive Go pipeline: `golangci-lint`, race-detector unit tests with coverage report, and cross-compile build verification. |
| **Go Release** | `.github/workflows/go-release.yml` | Cross-compilation and automated binary artifact packaging and publishing to GitHub Releases via GoReleaser. |
| **Docker Build & Push** | `.github/workflows/docker-build.yml` | Multi-platform (`amd64`, `arm64`) Docker image build using Buildx, automatic semantic tagging, and GHCR publishing with caching. |
| **Node.js CI** | `.github/workflows/node-ci.yml` | Universal Node.js pipeline supporting `npm`, `pnpm`, `yarn`, and `bun` for linting, testing, and building. |
| **Python CI** | `.github/workflows/python-ci.yml` | Python test & lint automation using `ruff` and `pytest` with pip dependency caching. |

---

### 📖 Quick Usage Examples

#### 1. Automated Semantic Release
Add `.github/workflows/release.yml` in your project:

```yaml
name: Release

on:
  push:
    branches:
      - main

permissions:
  contents: write

jobs:
  release:
    uses: faridlamaul/shipguard/.github/workflows/semantic-release.yml@v1.0.3
    with:
      bump: auto  # auto, major, minor, or patch
    secrets:
      token: ${{ secrets.GITHUB_TOKEN }}
```

| Input | Default | Description |
|---|---|---|
| `bump` | `auto` | `auto`, `major`, `minor`, or `patch` |
| `version` | | Explicit version, e.g. `1.0.0` |
| `dry_run` | `false` | Print the plan and release notes; tag and publish nothing |
| `draft` | `false` | Create a draft release |
| `prerelease` | | Prerelease identifier, e.g. `rc` for `vX.Y.Z-rc.N` |
| `shiptag_image` | `ghcr.io/faridlamaul/shiptag:0.3.0@sha256:…` | Image to run, pinned by digest |

Outputs: `released` (`true` or `false`) and `version`, the new tag such as `v1.2.3`.

---

#### 1b. Full Pipeline: Semantic Release + GoReleaser Binary Packaging
Combine SemVer versioning and multi-platform binary compilation in `.github/workflows/release.yml`.

##### Manual Trigger (Recommended for deliberate version control):
Allows selecting version bump type (`patch`, `minor`, `major`) via GitHub Actions UI:

```yaml
name: Release

on:
  workflow_dispatch:
    inputs:
      bump:
        description: "Version bump type"
        type: choice
        options:
          - patch
          - minor
          - major
          - auto
        default: patch
        required: true
      dry_run:
        description: "Dry-run (preview version without creating tag or release)"
        type: boolean
        default: false

permissions:
  contents: write

jobs:
  semantic:
    uses: faridlamaul/shipguard/.github/workflows/semantic-release.yml@v1.0.3
    with:
      bump: ${{ inputs.bump }}
      dry_run: ${{ inputs.dry_run }}
    secrets:
      token: ${{ secrets.GITHUB_TOKEN }}

  binary:
    needs: semantic
    if: needs.semantic.outputs.released == 'true' && !inputs.dry_run
    uses: faridlamaul/shipguard/.github/workflows/go-release.yml@v1.0.3
    with:
      version: ${{ needs.semantic.outputs.version }}
    secrets:
      token: ${{ secrets.GITHUB_TOKEN }}
```

##### Automatic Trigger on Push to Main:
Replace `on: workflow_dispatch` with `on: push: branches: [main]` to automatically calculate bump and release on every push.

---

#### 2. Go CI (Lint, Test, Build)
Add `.github/workflows/ci.yml` in your Go project:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  go-ci:
    uses: faridlamaul/shipguard/.github/workflows/go-ci.yml@v1.0.3
    with:
      go_version: '1.22'
      run_lint: true
      run_tests: true
      run_build: true
      build_output: bin/my-app
      build_package: ./cmd/my-app
```

---

#### 3. Docker Build & Push to GHCR
Add `.github/workflows/docker.yml` in your project:

```yaml
name: Docker

on:
  push:
    branches: [main]
    tags: ['v*']

permissions:
  contents: read
  packages: write

jobs:
  docker:
    uses: faridlamaul/shipguard/.github/workflows/docker-build.yml@v1.0.3
    with:
      image_name: ghcr.io/${{ github.repository }}
      platforms: linux/amd64,linux/arm64
      push: true
```

---

#### 4. Node.js / TypeScript CI
```yaml
name: Node CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  node:
    uses: faridlamaul/shipguard/.github/workflows/node-ci.yml@v1.0.3
    with:
      node_version: '20'
      package_manager: pnpm # or npm, yarn, bun
```

---

#### 5. Python CI
```yaml
name: Python CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  python:
    uses: faridlamaul/shipguard/.github/workflows/python-ci.yml@v1.0.3
    with:
      python_version: '3.11'
      run_lint: true
      run_tests: true
```

---

### 🔒 Security & Best Practices

- All workflows default to minimal permissions (`contents: read`).
- Workflows requiring write access (such as `semantic-release` creating git tags) explicitly declare `contents: write`.
- Works out-of-the-box with standard repository `GITHUB_TOKEN` — no manual Personal Access Tokens (PAT) needed unless triggering downstream workflows.
- Every action is pinned to a commit SHA and every image to a digest. Merges to `main` are released automatically by shiptag; the examples use `@v1.0.3`, and callers that want immutability can pin the release commit SHA with a `# vX.Y.Z` comment, which Dependabot keeps up to date.

---

## 📄 License

MIT License © 2026 Ahmad Lamaul Farid.
