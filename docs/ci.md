# shipguard ci

`shipguard ci` installs dependencies, then lints, tests and builds a project in CI, and writes the reports each platform can show. One language per repository; `dir` selects a subdirectory. Monorepos and multi-version matrices are out of scope.

Supported languages: Go, Node.js, Python, Ruby and Rust. The language and toolchain version are detected from the repository files; every default is pinned and every step can be overridden.

## Command

```bash
shipguard ci                  # install, lint, test, build
shipguard ci lint test        # only these steps (install always runs first)
shipguard ci detect           # prints: go 1.27 (go.mod)
shipguard ci detect --format json
```

`shipguard ci [install|lint|test|build ...]` runs the named steps in the fixed order install, lint, test, build. Every selected step runs even when an earlier one fails, so one run shows every problem; the only exception is that the other steps are skipped when `install` fails. `shipguard ci detect` prints the language, version and the file the version came from (`--format json` is for adapters).

| Flag | Variable | Meaning |
|---|---|---|
| `--dir` | `SHIPGUARD_DIR` | Project directory. Default: the CI workspace, else the current directory. |
| `--config` | `SHIPGUARD_CONFIG` | Config file. Default: `.shipguard.yaml` in the project directory. |
| `--language` | `SHIPGUARD_LANGUAGE` | Language (`go`, `golang`, `node`, `python`, `ruby`, `rust`). Overrides `ci.language`. |
| `--toolchain` | `SHIPGUARD_TOOLCHAIN` | Toolchain version. Overrides `ci.version`. |

The pinned tools are Linux binaries. Outside Linux only steps with your own `run` command work.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No step failed and at least one step passed. |
| `1` | At least one step failed (its command exited non-zero). |
| `2` | Tool or config error: language not detected or ambiguous, missing lockfile, missing toolchain, invalid `ci:` config, tool download or checksum failure, a step timeout, no step passed, or the run was cancelled by SIGINT/SIGTERM. Exit 2 wins over 1. |

A step that never ran never counts as a pass. A skipped step is reported with its reason.

## Defaults per language

A missing lockfile is exit 2. A step that does not apply is skipped with a reason in the summary. Dependencies install frozen from the lockfile. The version comes from `ci.version` (or `--toolchain`), then the repository files below, then the default in [`internal/ci/tools/ci-tools.env`](../internal/ci/tools/ci-tools.env), which also pins every downloaded tool.

| Language | Marker | Version from | Install | Lint | Test | Build |
|---|---|---|---|---|---|---|
| Go | `go.mod` | `toolchain`, else `go` directive | `go mod download` | golangci-lint (pinned); uses your `.golangci.yml` | gotestsum (pinned): `-race -coverprofile`; JUnit and Cobertura are produced | `go build ./...` |
| Node | `package.json` | `.nvmrc`, `.node-version`, `engines.node`, else the default | `package-lock.json`: `npm ci`; `pnpm-lock.yaml`: corepack pnpm `--frozen-lockfile`; `yarn.lock`: corepack yarn (`--immutable` for berry, else `--frozen-lockfile`); `bun.lock`/`bun.lockb`: pinned bun `--frozen-lockfile` | script `lint` | script `test` | script `build` |
| Python | `pyproject.toml` or `requirements.txt` | `.python-version`, `requires-python` (highest default that satisfies it), else the first default | uv (pinned): `uv.lock`: `uv sync --frozen`; `poetry.lock`: poetry (pinned, run by uv) `install --sync`; `requirements.txt` (+ `requirements-dev.txt`): venv + `uv pip install` | `ruff check .` and `ruff format --check .` (pinned) | `coverage run -m pytest --junitxml`, then `coverage xml`; pytest and coverage are installed at pinned versions when the project lacks them | `uv build` when `[build-system]` exists, else skipped |
| Ruby | `Gemfile` | `.ruby-version`, `ruby` in the Gemfile, else the default | `bundle config set --local frozen true`, `bundle install`; `Gemfile.lock` required | `bundle exec rubocop` when rubocop is in `Gemfile.lock`, else skipped | `bundle exec rspec` when `spec/` exists and rspec-core is locked; else `bundle exec rake test` when rake is locked; else skipped | `gem build` when exactly one gemspec exists; none: skipped; several: error |
| Rust | `Cargo.toml` | `channel` in `rust-toolchain.toml` or `rust-toolchain`, else the default | adds clippy and rustfmt with rustup when present, then `cargo fetch` | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` | `cargo nextest run` (pinned, JUnit), plus `cargo test --doc` when the package has a lib target | `cargo build --release` |

Notes:

- Cargo commands add `--locked` when `Cargo.lock` exists.
- Node reads the `scripts` keys of `package.json` by exact name (no substring matching). Exactly one lockfile must exist, and a `packageManager` field that names another manager is an error. Set `packageManager` (for example `pnpm@9.15.0`) for pnpm and yarn so corepack uses the version you expect; the pinned bun version comes from `ci-tools.env`. Node, Ruby and Rust steps produce JUnit and coverage only from the paths you give in `ci.steps.<step>.junit` and `.coverage`, except the Rust test step, which finds nextest's JUnit itself.
- Python runs every uv command with `UV_PYTHON=python3` and `UV_PYTHON_DOWNLOADS=never`, so it uses the interpreter of the job image or setup action and never downloads one. `requires-python` is read from the `[project]` table with a simple reader that understands single-line strings and the operators `>= > <= < == ~=`.
- Go with golangci-lint v2 needs a v2 `.golangci.yml`; see the [migration guide](https://golangci-lint.run/docs/product/migration-guide/).

## Configuration

The `ci:` key of `.shipguard.yaml` (all keys are documented in [configuration.md](configuration.md#ci-steps-ci)). Unlike the security policy, `ci` is read from the pull request head, because the build already runs the repository's own code. Unknown keys are errors (exit 2).

```yaml shipguard-config
ci:
  language: node        # optional; default: detected
  version: "22"         # optional; overrides the version from repository files
  timeouts:
    per_step: 30m       # default 30m
  steps:
    lint:  { run: "make lint" }        # replaces the default command (sh -c in the project dir)
    test:
      run: "make test"
      junit: ["reports/*.xml"]
      coverage: "coverage/cobertura.xml"
    build: { enabled: false }
```

- `run` replaces the step's default commands and also drops the default JUnit and coverage files of that step. Give `junit` and `coverage` again if your command writes them.
- `junit` is a list of globs; the matching files are merged into one report. `coverage` is a Cobertura file.
- `enabled: false` skips the step; setting `run` on a disabled step is an error.

## Outputs

Written to `.shipguard/ci/` in the project directory:

| File | Contents |
|---|---|
| `result.json` | Language, version and its source; each step with status (`passed`, `failed`, `skipped`), duration, exit code, reason and warnings. |
| `summary.md` | Step table, coverage percentage, and up to 20 failing tests (the rest is counted: "N more in .shipguard/ci/result.json"). |
| `test-results/junit.xml` | The merged JUnit of all steps. |
| `coverage.xml` | Cobertura coverage, when a step produced it. |

Per platform:

- **GitHub**: the summary goes to the job summary and failing tests become `::error file=...` annotations (at most 50). The composite action uploads `.shipguard/ci/` as the `shipguard-ci` artifact.
- **GitLab**: `artifacts:reports:junit` (Tests tab), `artifacts:reports:coverage_report` (Cobertura, line coverage in merge requests) and a `coverage:` regex that reads the `Coverage: NN.N%` line of the summary.
- **Bitbucket**: with `BITBUCKET_BUILD_NUMBER` set, the JUnit is also written to `test-results/junit.xml` at the clone root, which fills the Tests tab.

## GitHub

Two entry points. `vX.Y.Z` stands for the release you pin.

**Reusable workflow** for the common case:

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
    with:
      steps: "lint test build"   # empty runs every step
```

Inputs: `dir`, `language`, `version`, `steps`, `config`, `shipguard-version` and `runs-on`.

**Composite action** when the job needs `services:`, a matrix or extra steps. It runs inside your job:

```yaml
name: CI

on:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17
        env:
          POSTGRES_PASSWORD: postgres
        ports: ["5432:5432"]
    steps:
      - uses: actions/checkout@<sha> # pin
        with:
          persist-credentials: false
      - uses: faridlamaul/shipguard/adapters/github/ci@vX.Y.Z
        with:
          steps: "lint test"
```

Inputs: `dir`, `language`, `version`, `steps`, `config` and `shipguard-version`. Pinned at a version tag, the action downloads that release's archive and verifies `checksums.txt` with cosign and the archive against its entry in the file before running it. Pinned by full commit SHA (`@<sha> # vX.Y.Z`), it builds the binary from its own source with `actions/setup-go` instead: exact, but slower. The action then runs `shipguard ci detect`, sets up the toolchain (`actions/setup-go`, `setup-node`, `setup-python`, `ruby/setup-ruby`, or rustup with clippy and rustfmt), runs `shipguard ci` and uploads the results.

## GitLab

The component takes the image from its inputs, so the toolchain follows the repository. Pin an exact version without the `v` prefix (`X.Y.Z`):

```yaml
include:
  - component: gitlab.com/faridlamaul/shipguard/ci@X.Y.Z
    inputs:
      language: golang
      version: "1.27"
```

| Input | Default | Meaning |
|---|---|---|
| `language` | required | Image name: `golang`, `node`, `python`, `ruby` or `rust`. |
| `version` | required | Image tag, which is also the toolchain version (`1.27`, `22`). |
| `registry` | `""` | Registry prefix with a trailing slash, for mirrors. |
| `dir` | `.` | Project directory. |
| `steps` | `""` | Space separated `lint`, `test`, `build`. Empty runs all. |
| `config` | `.shipguard.yaml` | Config file. |
| `stage` | `test` | Stage of the job. |

The job downloads the release binary and checks its SHA-256, rendered into the template at release time, before extracting it. If the repository's version files name a different toolchain than the image, `shipguard ci` prints a warning; a different language is exit 2. The job publishes the JUnit and Cobertura reports and the `coverage:` percentage described above. `-slim` and `-alpine` images lack `curl`; install it first (`apt-get update && apt-get install -y curl ca-certificates`).

## Bitbucket

Bitbucket has no component catalog, so the steps are a snippet you copy.

1. Download `build-test-pipelines.yml` from the [GitHub release](https://github.com/faridlamaul/shipguard/releases) you want to use. The release copy has the version and the SHA-256 of the linux archives filled in; the file under `examples/bitbucket/` is the unrendered source.
2. Verify it before copying; the file carries the hashes of the binary it downloads, so this is the trust anchor:

   ```bash
   gh attestation verify build-test-pipelines.yml --repo faridlamaul/shipguard
   ```

   The release run also prints the file's SHA-256 in its job summary.
3. Copy the steps into your `bitbucket-pipelines.yml`. Keep the `&shipguard-ci` anchor in a step that stays in the file: the other languages reuse it with `*shipguard-ci`.
4. Pick the image of each step (`golang:1.27`, `node:22`, ...) and set `SHIPGUARD_LANGUAGE` and `SHIPGUARD_TOOLCHAIN` to match.

To pin a version, use the file of that release; the script downloads exactly that version and checks its SHA-256 before extracting it. To upgrade, replace the steps with the file of the newer release.

Optional variables, exported before the shared script line: `SHIPGUARD_DIR` (project directory), `SHIPGUARD_CONFIG` (config file) and `SHIPGUARD_CI_STEPS` (space separated `lint`, `test`, `build`; empty runs every configured step).

`-slim` and other minimal images lack `curl`; the step stops with a message. Install it first with `apt-get update && apt-get install -y curl ca-certificates`.

Test reports appear on their own: `shipguard ci` writes `test-results/junit.xml` at the clone root when `BITBUCKET_BUILD_NUMBER` is set, and Bitbucket collects `**/test-results/**/*.xml` into the Tests tab. The summary is printed at the end of the step log, and the step keeps the exit code of `shipguard ci`.

## Security

- Pinned tools are downloaded over HTTPS only, verified against the SHA-256 in `ci-tools.env` before they run, and cached by version and hash in `.shipguard-cache/tools/`.
- The shipguard binary is verified by the hash rendered into each template at release time (GitLab, Bitbucket), or by cosign and `checksums.txt` (GitHub composite action). A mismatch fails the job.
- Repository code and `ci.steps.<step>.run` are the repository's own trusted code, like its Makefile. The trust boundary is the platform's: fork pipelines get no secrets. The adapters add no secrets and need no tokens, but the job gives every CI variable to the code under test, so keep secrets in protected variables.
- The GitHub adapters use `contents: read`, `persist-credentials: false`, pass inputs only through `env:`, and are checked with zizmor and actionlint. `steps` accepts lowercase letters and spaces only.

## Migrating from the legacy workflows

`go-ci.yml`, `node-ci.yml` and `python-ci.yml` are deprecated, print a warning and are removed in the next major release. Replace them with `build-test.yml` (above) or the composite action:

| Legacy | Now |
|---|---|
| `go-ci.yml` with `go_version` | `build-test.yml`; the version comes from `go.mod` or the `version` input. Needs a golangci-lint v2 config. |
| `node-ci.yml` with `node_version`, `package_manager` | `build-test.yml`; the lockfile selects the manager, `pnpm` and `yarn` need `packageManager` in `package.json`. |
| `python-ci.yml` with `python_version` | `build-test.yml`; needs `uv.lock`, `poetry.lock` or `requirements.txt`. |
