# shipguard on GitLab

> **Status: adapter in development; not yet released.** The GitLab component and templates are not built yet, and the image and version tags do not exist. This page describes the planned usage. It will be confirmed when the first release ships.

The adapter will be a CI/CD component that runs `shipguard run` in the shipguard image, then publishes the reports as job artifacts. `X.Y.Z` stands for the release version. GitLab tags have no `v` prefix.

## Quick start

Add to `.gitlab-ci.yml` (also in [`examples/gitlab/.gitlab-ci.yml`](../examples/gitlab/.gitlab-ci.yml)):

```yaml
include:
  - component: gitlab.com/faridlamaul/shipguard/scan@X.Y.Z
    inputs:
      scanners: all
      mode: enforce
      config: .shipguard.yaml
```

Self-managed GitLab cannot use the gitlab.com catalog, so include the rendered template by URL and pin its hash:

```yaml
include:
  - remote: https://gitlab.com/faridlamaul/shipguard/-/raw/X.Y.Z/templates/scan.yml
    integrity: sha256-<published hash>
    inputs: { scanners: all, mode: enforce, config: .shipguard.yaml }
```

The component and the remote URL serve the same file, rendered at release time with the matching image tag.

## Inputs

| Input | Default | Description |
|---|---|---|
| `scanners` | `all` | `all`, or a comma list of `secrets`, `sast`, `sca`, `iac`. |
| `mode` | empty | `enforce` or `audit`. Empty uses the `mode` from `.shipguard.yaml`. |
| `config` | `.shipguard.yaml` | Path to the config file. |
| `image` | the release image | Image override. |

Reports are always produced as job artifacts: `.shipguard/` (including `findings.json` and `summary.md`) and the GitLab report files.

## Full history

Merge request and scheduled scans need the whole git history. The job sets `GIT_DEPTH: 0`. If you override the clone depth in your project settings, keep it at 0; otherwise shipguard exits with code 2 and says why. It never scans the wrong range silently.

Merge request pipelines are detected from `CI_PIPELINE_SOURCE=merge_request_event` and diffed against `CI_MERGE_REQUEST_DIFF_BASE_SHA`. Add a pipeline schedule (Build > Pipeline schedules) so the full tree and the full history are scanned regularly.

## Policy on merge requests

On a merge request the policy is read from the base, and the summary warns when the MR changes `.shipguard.yaml`. Protect the file with a CODEOWNERS entry and approval rules, and add it in its own MR before you enforce. See [Configuration](configuration.md#pull-requests-the-policy-comes-from-the-base).

## Hardening

- Pin the component to an exact version (`scan@X.Y.Z`), never a floating one. For `include: remote`, keep the `integrity` hash.
- Pin the image by digest with the `image` input: `ghcr.io/faridlamaul/shipguard:vX.Y.Z@sha256:<digest>`.
- Verify the image signature. **Planned for the first release (not yet implemented):** no signing or attestation step exists yet, so this command is an illustrative future example. The exact certificate identity will be documented when the release workflow lands.


  ```bash
  cosign verify ghcr.io/faridlamaul/shipguard:vX.Y.Z \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/faridlamaul/shipguard/\.github/workflows/.+@refs/tags/v.+$'
  ```

## Tier notes

The security dashboard and merge request security widgets need GitLab Ultimate. On other tiers the artifacts are still produced and the summary is printed in the job log.
