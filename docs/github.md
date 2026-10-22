# shipguard on GitHub

shipguard ships as a reusable workflow and as a composite action. The reusable workflow is the one to use: it checks out the full history, runs the scan in the shipguard image, writes the job summary and uploads SARIF to Code Scanning.

This page writes `vX.Y.Z` for the release tag you pin; see [Releases](https://github.com/faridlamaul/shipguard/releases). Pinning a commit SHA of `faridlamaul/shipguard` also works; the workflow then builds the image from source, which is exact but slower.

## Quick start

Add `.github/workflows/security.yml` (also in [`examples/github/security.yml`](../examples/github/security.yml)):

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

The caller must grant all three permissions:

| Permission | Why |
|---|---|
| `contents: read` | Check out the repository. |
| `security-events: write` | Upload SARIF to Code Scanning. |
| `actions: read` | `upload-sarif` needs it on private repositories. |

The push and schedule triggers matter. Pull requests are gated on new findings only; pushes to the default branch and scheduled runs scan the whole tree, and scheduled runs also scan the full git history for secrets. Add a schedule so that new CVEs in old dependencies are caught.

## Inputs

| Input | Default | Description |
|---|---|---|
| `scanners` | `all` | `all`, or a comma list of `secrets`, `sast`, `sca`, `iac`. |
| `mode` | empty | `enforce` or `audit`. Empty uses the `mode` from `.shipguard.yaml`. |
| `config` | `.shipguard.yaml` | Path to the config file. A custom path must exist. |
| `image` | empty | Image to run. Empty means `ghcr.io/faridlamaul/shipguard:<tag>` when the workflow is called at a version tag, otherwise a build from source. |
| `upload_sarif` | `auto` | `auto`, `true` or `false`. With `auto`, a refused upload is a warning instead of a failure. |

## Outputs

| Output | Description |
|---|---|
| `result` | `pass`, `fail` or `audit`. |
| `new_findings` | Number of new findings. |
| `total_findings` | Total number of findings. |

The results are also written to `.shipguard/` in the workspace and to the job summary.

## Full history

PR and scheduled scans need the whole git history. The reusable workflow checks out with `fetch-depth: 0` itself. If you use the composite action directly (`faridlamaul/shipguard/adapters/github@vX.Y.Z`), set `fetch-depth: 0` on your own `actions/checkout` step.

## Advanced environment variables

The reusable workflow has no environment inputs, and a caller cannot set the environment of the workflow it calls. Variables such as `SHIPGUARD_OSV_OFFLINE_DB`, `SHIPGUARD_TRIVY_CHECKS_BUNDLE_REPOSITORY` and `SHIPGUARD_EVENT` therefore need the composite action, with `env:` on the job or step. The action forwards every `SHIPGUARD_*` variable into the container:

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write, actions: read }
    steps:
      - uses: actions/checkout@<sha> # pin
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: faridlamaul/shipguard/adapters/github@vX.Y.Z
        env:
          SHIPGUARD_TRIVY_CHECKS_BUNDLE_REPOSITORY: registry.example.com/trivy-checks
          SHIPGUARD_OSV_OFFLINE_DB: ${{ github.workspace }}/osv-db
```

The offline database path must be inside the workspace, which is the only directory mounted into the container.

## Releases

`release-artifacts.yml` versions the repository, publishes its binaries and its container image, and attests them. Call it from a workflow on your default branch:

```yaml
name: Release

on:
  push:
    branches: [main]

jobs:
  release:
    uses: faridlamaul/shipguard/.github/workflows/release-artifacts.yml@vX.Y.Z
    permissions: { contents: write, packages: write, id-token: write, attestations: write }
```

Inputs: `steps`, `dir`, `config`, `prerelease`, `dry-run`, `shipguard-version` and `runs-on`. Outputs: `released`, `tag`, `version`, `image` and `image_digest`. See [shipguard release](release.md) for the steps, the image gate and the configuration.

## Policy on pull requests

On a pull request the policy is read from the base branch, and the summary warns when the PR changes `.shipguard.yaml`. Protect that file with CODEOWNERS, and add it in its own PR before you enforce. See [Configuration](configuration.md#pull-requests-the-policy-comes-from-the-base).

## Hardening

**Pin the workflow by commit SHA.** A tag can move; a SHA cannot. Keep the version in a comment so Dependabot can update it:

```yaml
uses: faridlamaul/shipguard/.github/workflows/scan.yml@<full-commit-sha> # vX.Y.Z
```

A workflow pinned by SHA builds the image from source. To get a fast, exact run, also pin the image by digest:

```yaml
with:
  image: ghcr.io/faridlamaul/shipguard:vX.Y.Z@sha256:<digest>
```

**Verify the image.** The release workflow signs each image with cosign keyless signing (GitHub OIDC) and attaches SLSA build provenance and an SBOM. The image is built by the `release.yml` run on `main`, so that is the certificate identity:

```bash
cosign verify ghcr.io/faridlamaul/shipguard:vX.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/faridlamaul/shipguard/.github/workflows/release.yml@refs/heads/main
gh attestation verify oci://ghcr.io/faridlamaul/shipguard:vX.Y.Z --repo faridlamaul/shipguard
```

**Scanner binaries.** Each scanner in the image is pinned by version and SHA-256 in `versions.env`, and the image build fails on a mismatch. opengrep publishes no checksums file, so its binaries are verified against the SHA-256 digest GitHub records for each release asset: that digest comes from the same GitHub release channel as the binary, so it protects against corruption and later tampering, not against a compromised upstream release.

**What the container sees.** The scan runs in the image with only the workspace mounted. `GITHUB_TOKEN`, the runner command files and other secrets are not passed in; the adapter forwards an explicit allowlist of variables.

## Tier notes

- Code Scanning on a **private** repository needs GitHub Advanced Security. Without it, a SARIF upload is refused. With `upload_sarif: auto` that is a warning and the gate still works from the job summary and the exit code.
- Pull requests from forks get a read-only token, so the SARIF upload is refused there as well.
