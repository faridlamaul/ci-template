# shipguard on Bitbucket

On Bitbucket the shipguard image is the pipe. `vX.Y.Z` stands for the release tag.

## Quick start

Add a step to `bitbucket-pipelines.yml` (also in [`examples/bitbucket/bitbucket-pipelines.yml`](../examples/bitbucket/bitbucket-pipelines.yml)):

```yaml
pipelines:
  default:
    - step:
        name: security
        script:
          - pipe: docker://ghcr.io/faridlamaul/shipguard:vX.Y.Z
            variables:
              SCANNERS: all
              MODE: enforce
              CONFIG: .shipguard.yaml
```

## Variables

| Variable | Default | Description |
|---|---|---|
| `SCANNERS` | `all` | `all`, or a comma list of `secrets`, `sast`, `sca`, `iac`. |
| `MODE` | empty | `enforce` or `audit`. Empty uses the `mode` from `.shipguard.yaml`. |
| `CONFIG` | `.shipguard.yaml` | Path to the config file. |
| `CODE_INSIGHTS` | `true` | Set to `false` to skip the Code Insights report. |

These bare names are read only on Bitbucket. The `SHIPGUARD_*` forms work too, and win when both are set. See [Configuration](configuration.md#environment-variables).

## Pull requests and schedules

Pull request pipelines are detected from `BITBUCKET_PR_ID` and diffed against `BITBUCKET_PR_DESTINATION_BRANCH`. Run the pipe in a `pull-requests` pipeline for that, and in a branch pipeline for the default branch.

**Scheduled pipelines.** Bitbucket exposes no variable that says a run is scheduled, so a scheduled custom pipeline must set `SHIPGUARD_EVENT=schedule` itself, as a pipe variable. Without it the run is treated as a push, so it skips the full-history secrets scan:

```yaml
pipelines:
  custom:
    nightly-security:
      - step:
          name: security
          script:
            - pipe: docker://ghcr.io/faridlamaul/shipguard:vX.Y.Z
              variables:
                SCANNERS: all
                SHIPGUARD_EVENT: schedule
```

**Full history.** Bitbucket clones are shallow by default. shipguard runs `git fetch --unshallow` itself when it needs the history, so you do not need to set `clone: depth: full`. If that fetch fails, shipguard exits with code 2 rather than scanning the wrong range.

## Code Insights

Results are posted as a Code Insights report on the commit. By default shipguard posts through the Pipelines proxy, which needs no token. As a pipe it reaches the proxy at `http://host.docker.internal:29418`; when the image runs as a step image, at `http://localhost:29418`. Related variables:

| Variable | Description |
|---|---|
| `SHIPGUARD_BITBUCKET_PROXY` | Override the proxy URL. Set `none` to post directly with no proxy; you then need `SHIPGUARD_BITBUCKET_TOKEN`, or the upload fails (a warning only). An invalid URL is an upload error (a warning naming the variable, not its value). |
| `SHIPGUARD_BITBUCKET_TOKEN` | Bearer token for the Bitbucket API. When set, the proxy is not used. |

A failed upload is a warning. It never changes the gate result.

## Policy on pull requests

The policy is read from the destination branch, and the summary warns when the PR changes `.shipguard.yaml`. Bitbucket has no CODEOWNERS file, so use default reviewers or a merge check on that path. Add the file in its own PR before you enforce. See [Configuration](configuration.md#pull-requests-the-policy-comes-from-the-base).

## Hardening

- Pin the pipe to an exact tag, or better to a digest: `docker://ghcr.io/faridlamaul/shipguard:vX.Y.Z@sha256:<digest>`.
- Verify the image signature and its build provenance. The image is signed keylessly by the `release.yml` run on `main` of the GitHub repository:

  ```bash
  cosign verify ghcr.io/faridlamaul/shipguard:vX.Y.Z \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity https://github.com/faridlamaul/shipguard/.github/workflows/release.yml@refs/heads/main
  gh attestation verify oci://ghcr.io/faridlamaul/shipguard:vX.Y.Z --repo faridlamaul/shipguard
  ```

## Air-gapped runs

Point trivy and osv-scanner at your mirrors with `SHIPGUARD_TRIVY_CHECKS_BUNDLE_REPOSITORY` and `SHIPGUARD_OSV_OFFLINE_DB`. See [Configuration](configuration.md#other-variables).
