# Contributing to shipguard

Thanks for helping improve shipguard. Bug reports, fixes, and features are all welcome.

## Before you start

- **Questions:** open an [issue](https://github.com/faridlamaul/shipguard/issues) with your question.
- **Bugs:** open an issue. The shipguard version, the CI platform, and the `.shipguard/findings.json` summary (without secrets) make most bugs reproducible.
- **Features and larger changes:** open an issue first so we can agree on the approach before you write code.
- **Security issues:** do not open a public issue; follow [SECURITY.md](SECURITY.md).

## Development setup

You need Go 1.26 or newer and git. Docker is needed only for the image and end-to-end tests.

```bash
git clone https://github.com/faridlamaul/shipguard.git
cd shipguard
make build                       # bin/shipguard
make fmt-check vet test          # what CI runs on every pull request
make docs-check                  # validates the .shipguard.yaml snippets in the docs
make e2e                         # builds the image and runs the end-to-end tests
```

| Path | Contents |
|---|---|
| `cmd/shipguard` | CLI wiring (`scan`, `gate`, `report`, `run`) |
| `internal/policy` | `.shipguard.yaml` parsing and the gate decision |
| `internal/scan` | Running scanners and the PR base comparison |
| `internal/scanner` | gitleaks, opengrep, osv-scanner and trivy wrappers |
| `internal/report` | Summary, SARIF, GitLab reports and Bitbucket Code Insights |
| `internal/platform` | CI platform and event detection |
| `adapters/` | The GitHub action (GitLab and Bitbucket are in development) |
| `rules/` | Curated SAST rules with their test cases |
| `schema/` | JSON Schemas for `.shipguard.yaml` and `findings.json` |
| `docs/`, `examples/` | User documentation and example pipelines |

## Tests

- Add or update tests with every change. Tests that need a repository create one with `internal/testutil/gitfixture`, which isolates them from your global git config.
- Scanner tests use recorded tool output; never call a real network service.
- Every SAST rule needs positive and negative test cases that pass `opengrep --test`.
- When you change a documented key or variable, update the docs. `make docs-check` fails if a `.shipguard.yaml` snippet no longer parses.

## Pull requests

Pull requests are squash-merged, and **the PR title becomes the commit message**. The title must be a [Conventional Commit](https://www.conventionalcommits.org/):

| Title | Effect |
|---|---|
| `feat(scan): add a scanner flag` | minor release |
| `fix(report): escape table cells` | patch release |
| `feat!: rename a config key` | major release |
| `docs: …`, `chore: …`, `ci: …`, `test: …`, `refactor: …` | no release |

A breaking change also needs a `BREAKING CHANGE:` paragraph in the PR description explaining what users must change.

Keep each pull request focused on one change, and update the README and docs when behavior or flags change. shipguard scans itself, so a PR that adds a finding to this repository fails the same gate it ships.

## Releases

Maintainers do not tag releases by hand. Every merge to `main` runs the release workflow, which tags the version and publishes the release.
