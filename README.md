# 🚀 ci-template

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Actions](https://img.shields.io/badge/GitHub-Actions-2088FF?logo=github-actions&logoColor=white)]()

A centralized repository of **reusable GitHub Actions workflows** (`workflow_call`) designed for modern open-source projects.

Instead of duplicating hundreds of lines of CI/CD YAML across every repository, consume these modular workflows with just a few lines of configuration.

---

## 📦 Available Reusable Workflows

| Workflow | Path | Description |
|---|---|---|
| **Semantic Release** | `.github/workflows/semantic-release.yml` | Automated Conventional Commits semver bumping, changelog generation, git tagging, and GitHub Releases via [`go-gitops`](https://github.com/faridlamaul/go-gitops) container image from GHCR (zero Go setup required). |
| **Go CI** | `.github/workflows/go-ci.yml` | Comprehensive Go pipeline: `golangci-lint`, race-detector unit tests with coverage report, and cross-compile build verification. |
| **Docker Build & Push** | `.github/workflows/docker-build.yml` | Multi-platform (`amd64`, `arm64`) Docker image build using Buildx, automatic semantic tagging, and GHCR publishing with caching. |
| **Node.js CI** | `.github/workflows/node-ci.yml` | Universal Node.js pipeline supporting `npm`, `pnpm`, `yarn`, and `bun` for linting, testing, and building. |
| **Python CI** | `.github/workflows/python-ci.yml` | Python test & lint automation using `ruff` and `pytest` with pip dependency caching. |

---

## 📖 Quick Usage Examples

### 1. Automated Semantic Release
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
    uses: faridlamaul/ci-template/.github/workflows/semantic-release.yml@main
    with:
      bump: auto  # auto, major, minor, or patch
    secrets:
      token: ${{ secrets.GITHUB_TOKEN }}
```

---

### 2. Go CI (Lint, Test, Build)
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
    uses: faridlamaul/ci-template/.github/workflows/go-ci.yml@main
    with:
      go_version: '1.22'
      run_lint: true
      run_tests: true
      run_build: true
      build_output: bin/my-app
      build_package: ./cmd/my-app
```

---

### 3. Docker Build & Push to GHCR
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
    uses: faridlamaul/ci-template/.github/workflows/docker-build.yml@main
    with:
      image_name: ghcr.io/${{ github.repository }}
      platforms: linux/amd64,linux/arm64
      push: true
```

---

### 4. Node.js / TypeScript CI
```yaml
name: Node CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  node:
    uses: faridlamaul/ci-template/.github/workflows/node-ci.yml@main
    with:
      node_version: '20'
      package_manager: pnpm # or npm, yarn, bun
```

---

### 5. Python CI
```yaml
name: Python CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  python:
    uses: faridlamaul/ci-template/.github/workflows/python-ci.yml@main
    with:
      python_version: '3.11'
      run_lint: true
      run_tests: true
```

---

## 🔒 Security & Best Practices

- All workflows default to minimal permissions (`contents: read`).
- Workflows requiring write access (such as `semantic-release` creating git tags) explicitly declare `contents: write`.
- Works out-of-the-box with standard repository `GITHUB_TOKEN` — no manual Personal Access Tokens (PAT) needed unless triggering downstream workflows.

---

## 📄 License

MIT License © 2026 Ahmad Lamaul Farid.
