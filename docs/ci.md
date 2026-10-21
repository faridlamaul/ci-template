# shipguard ci

`shipguard ci` installs dependencies, then lints, tests and builds a project in CI, and writes the reports each platform can show. One language per repository; `dir` selects a subdirectory. Monorepos and multi-version matrices are out of scope.

Supported languages: Go, Node.js, Python, Ruby and Rust. The language and toolchain version are detected from the repository files; the defaults are opinionated and every step can be overridden. Tools that shipguard downloads are pinned and hash-verified (see Security).

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

The pinned tools are Linux binaries. Outside Linux, every step that uses a pinned tool needs a `run` override or `enabled: false`; the npm, pnpm and yarn Node steps need none.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No step failed and at least one requested step passed. `install` counts only when it is the only step requested (`shipguard ci install`). |
| `1` | At least one step failed (its command exited non-zero). |
| `2` | Tool or config error: language not detected or ambiguous, missing lockfile, missing toolchain, invalid `ci:` config, tool download or checksum failure, a step timeout, no requested step passed (a run where only `install` ran and every other step was skipped), or the run was cancelled by SIGINT/SIGTERM. Exit 2 wins over 1. |

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

- `cargo fetch`, `clippy`, `test` and `build` add `--locked` when `Cargo.lock` exists; `cargo fmt` does not.
- Node reads the `scripts` keys of `package.json` by exact name (no substring matching). Exactly one lockfile must exist, and a `packageManager` field that names another manager is an error. Set `packageManager` (for example `pnpm@9.15.0`) for pnpm and yarn so corepack uses the version you expect. Node 25 and later ship without corepack: when the image has none, the install step first runs `npm install -g corepack@<COREPACK_VERSION>` (the version in `ci-tools.env`); the pinned bun version comes from `ci-tools.env`. Node, Ruby and Rust steps produce JUnit and coverage only from the paths you give in `ci.steps.<step>.junit` and `.coverage`, except the Rust test step, which finds nextest's JUnit itself.
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
- **Bitbucket**: no copy is needed. Bitbucket scans `**/test-results/**/*.xml`, hidden directories included, so it finds `.shipguard/ci/test-results/junit.xml` itself and fills the Tests tab.

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

Inputs: `dir`, `language`, `version`, `steps`, `config` and `shipguard-version`. Node ranges from `engines.node` (`>=18`, `^20`, `>=18 <21`) work on GitHub: the version is passed unchanged to `actions/setup-node`. Pinned at a version tag, the action downloads that release's archive and verifies `checksums.txt` with cosign and the archive against its entry in the file before running it. Pinned by full commit SHA (`@<sha> # vX.Y.Z`), it builds the binary from its own source with `actions/setup-go` instead: exact, but slower. Any other ref also builds from source, including the moving major tag (`@v1`) of the action or the reusable workflow, because the ref is not `vX.Y.Z`: pin `@vX.Y.Z` or a full SHA (Dependabot and Renovate bump both), or set `shipguard-version` to download that release. The action then runs `shipguard ci detect`, sets up the toolchain (`actions/setup-go`, `setup-node`, `setup-python`, `ruby/setup-ruby`, or rustup with clippy and rustfmt), runs `shipguard ci` and uploads the results.

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
| `version` | required | Image tag, which selects the toolchain (`1.27`, `22`). The repository's version files are compared with it; a mismatch warns. |
| `registry` | `""` | Registry prefix with a trailing slash, for mirrors. |
| `dir` | `.` | Project directory. |
| `steps` | `""` | Space separated `lint`, `test`, `build`. Empty runs all. |
| `config` | `.shipguard.yaml` | Config file. |
| `stage` | `test` | Stage of the job. |

The job downloads the release binary and checks its SHA-256, rendered into the template at release time, before extracting it. The job sets `SHIPGUARD_LANGUAGE` but not `SHIPGUARD_TOOLCHAIN`: the image tag selects the toolchain, and when the repository's version files (`.nvmrc`, `go.mod`, ...) name a different one, `shipguard ci` prints a warning; a different language is exit 2. The job publishes the JUnit and Cobertura reports and the `coverage:` percentage described above. The version comes from the image tag on GitLab and from the step image on Bitbucket, not from ranges in repository files. `-slim` and `-alpine` images lack `curl`; install it first (`apt-get update && apt-get install -y curl ca-certificates` on Debian, `apk add --no-cache curl ca-certificates` on Alpine). On `golang:*-alpine`, the default Go test step runs with `-race`, which needs cgo and gcc, and musl images have no gcc: add `build-base`, or set `ci.steps.test.run` to a command without `-race`. The component has no pre-step input, so extend its job:

```yaml
shipguard-ci:
  before_script:
    - apk add --no-cache curl ca-certificates build-base
```

A job in your `.gitlab-ci.yml` with the same name is merged into the component's job.

## Bitbucket

Bitbucket has no component catalog, so the steps are a snippet you copy.

1. Download `build-test-pipelines.yml` from the [GitHub release](https://github.com/faridlamaul/shipguard/releases) you want to use. The release copy has the version and the SHA-256 of the linux archives filled in; the file under `examples/bitbucket/` is the unrendered source.
2. Verify it before copying; the file carries the hashes of the binary it downloads, so this is the trust anchor:

   ```bash
   gh attestation verify build-test-pipelines.yml --repo faridlamaul/shipguard
   ```

   The release run also prints the file's SHA-256 in its job summary.
3. Copy the steps into your `bitbucket-pipelines.yml`. Keep the `&shipguard-ci` anchor in a step that stays in the file: the other languages reuse it with `*shipguard-ci`.
4. Pick the image of each step (`golang:1.27`, `node:22`, ...) and set `SHIPGUARD_LANGUAGE` to match. Leave `SHIPGUARD_TOOLCHAIN` unset: the image selects the toolchain, and `shipguard ci` compares the repository's version files with it and warns on a mismatch. `SHIPGUARD_TOOLCHAIN` would replace the detected version and hide that warning.

To pin a version, use the file of that release; the script downloads exactly that version and checks its SHA-256 before extracting it. To upgrade, replace the steps with the file of the newer release.

Optional variables, exported before the shared script line: `SHIPGUARD_DIR` (project directory), `SHIPGUARD_CONFIG` (config file) and `SHIPGUARD_CI_STEPS` (space separated `lint`, `test`, `build`; empty runs every configured step).

`-slim` and other minimal images lack `curl`; the step stops with a message. Install it first with `apt-get update && apt-get install -y curl ca-certificates`.

Test reports appear on their own: Bitbucket collects `**/test-results/**/*.xml`, hidden directories included, so it finds `.shipguard/ci/test-results/junit.xml` itself and fills the Tests tab. The summary is printed at the end of the step log, and the step keeps the exit code of `shipguard ci`.

## Security

- The tools in [`ci-tools.env`](../internal/ci/tools/ci-tools.env) (golangci-lint, gotestsum, ruff, uv, cargo-nextest, bun) are downloaded over HTTPS only, verified against their SHA-256 before they run, and cached in `.shipguard-cache/tools/` by version. The cache entry records the pinned archive hash and the SHA-256 of the extracted executable; each use re-hashes the executable and downloads the tool again when it does not match. Not covered by hashes: Python test dependencies (pytest, coverage, poetry) and corepack (installed with npm only when the image lacks it) are pinned by version only; package managers (npm, bundler, corepack pnpm and yarn) and the toolchain come from the image or setup action; rustup components (clippy, rustfmt) are not pinned.
- The shipguard binary is verified by the hash rendered into each template at release time (GitLab, Bitbucket), or by cosign and `checksums.txt` (GitHub composite action). A mismatch fails the job.
- Repository code and `ci.steps.<step>.run` are the repository's own trusted code, like its Makefile. The trust boundary is the platform's: fork pipelines get no secrets. The adapters add no secrets and need no tokens, but the job gives every CI variable to the code under test, so keep secrets in protected variables.
- The GitHub adapters use `contents: read`, `persist-credentials: false`, pass inputs only through `env:`, and are checked with zizmor and actionlint. `steps` accepts lowercase letters and spaces only.

## Migrating from the legacy workflows

`go-ci.yml`, `node-ci.yml` and `python-ci.yml` are deprecated, print a warning and are removed in the next major release. Replace them with `build-test.yml` (above) or the composite action:

| Legacy | Now |
|---|---|
| `go-ci.yml` | `build-test.yml`. The version comes from `go.mod` (a `go` directive is now required) or the `version` input; the legacy default 1.22 no longer applies. A golangci-lint v2 config is required by both. `run_lint`, `run_tests`, `run_build` map to `steps:`; `build_output` and `build_package` have no input, use `ci.steps.build.run`. |
| `node-ci.yml` | `build-test.yml`. The lockfile selects the manager. The legacy workflow requires `packageManager` in `package.json` for pnpm and yarn; shipguard ci recommends it (a different manager is an error). Without a version file the default is the Node version in `ci-tools.env`, not 20. `run_lint`, `run_tests`, `run_build` map to `steps:` or `ci.steps.<step>.enabled: false`. |
| `python-ci.yml` | `build-test.yml`. Needs `uv.lock`, `poetry.lock` or `requirements.txt`. Without a version file the default is the first Python in `ci-tools.env`, not 3.11. Lint also runs `ruff format --check .`. `run_lint` and `run_tests` map to `steps:` or `ci.steps.<step>.enabled: false`. |
