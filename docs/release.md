# shipguard release

`shipguard release` versions a release and publishes its binaries and its container image. The image is built to a local OCI layout and scanned first; one that fails the policy never reaches the registry. The digest that was scanned is the digest that is pushed and signed.

It orchestrates pinned tools (shiptag, GoReleaser, trivy, crane, cosign; downloaded and hash-verified like the `shipguard ci` tools) and `docker buildx` from the runner. The CLI never handles registry tokens: crane and cosign read the docker config (log in before the run) and the ambient OIDC identity.

## Command

```bash
shipguard release                  # every applicable step
shipguard release version image    # only these steps, always in the order version, binaries, image
shipguard release --dry-run        # preview, publishes nothing
shipguard release --prerelease rc  # release a prerelease (passed to shiptag)
```

| Flag | Variable | Meaning |
|---|---|---|
| `--dir` | `SHIPGUARD_DIR` | Repository directory. Default: the CI workspace, else the current directory. |
| `--config` | `SHIPGUARD_CONFIG` | Config file. Default: `.shipguard.yaml` in the repository directory. |
| `--dry-run` | `SHIPGUARD_DRY_RUN` | Preview; see [Dry run](#dry-run). |
| `--prerelease` | `SHIPGUARD_PRERELEASE` | Prerelease identifier for the version step. |

## Steps

| Step | Applies when | Does |
|---|---|---|
| `version` | always | Runs `shiptag tag` and reads `released` and `tag`. If nothing is released but `HEAD` carries an exact `vX.Y.Z` tag, that tag is used (a re-run). Otherwise the command ends with exit 0, `released=false` and the later steps skipped. |
| `binaries` | `.goreleaser.yaml` or `.goreleaser.yml` exists | `goreleaser release --clean` at the tag. The pinned cosign is on `PATH`, so a `signs:` block in your GoReleaser config can sign `checksums.txt`. |
| `image` | the configured Dockerfile exists | Builds, scans, pushes, tags and signs the image (below). |

A step that does not apply is `skipped` with a reason. A failed step marks every later step `not run`.

### Image

1. `docker buildx build` for each configured platform with BuildKit SBOM and max-mode provenance, to a local OCI layout. `VERSION` is always passed as a build argument (`X.Y.Z`). A missing buildx builder is an error that names `docker/setup-buildx-action`.
2. `trivy image` scans each platform. Vulnerabilities become SCA findings and the existing `policy.fail_on.sca` threshold and `exceptions` decide. A block prints the findings, writes `image-findings.json`, exits 1 and pushes nothing.
3. If `<name>:vX.Y.Z` already exists with the same digest, the push is skipped (a re-run). With a different digest it is an error: a published tag is never moved.
4. `crane push` of the layout, then `crane tag` for the other tags.
5. `cosign sign --yes <name>@<digest>` (keyless).

Tags: `vX.Y.Z`, `X.Y.Z`, `vX.Y` and `vX`. A prerelease (a version containing `-`) gets only `vX.Y.Z` and `X.Y.Z`. There is no `latest`, `sha-` or branch tag.

Re-running an older version moves its `vX.Y` and `vX` tags back to that version's image. Run an old version only when you mean to.

## Configuration

An optional top-level `release:` key in `.shipguard.yaml`, read from the checked-out tree and validated like the rest (unknown keys are errors). Without it the defaults apply.

```yaml shipguard-config
release:
  image:
    name: ghcr.io/faridlamaul/faridlamaul-portfolio   # default ghcr.io/<owner>/<repo> from GITHUB_REPOSITORY
    dockerfile: Dockerfile                             # default Dockerfile
    context: .                                         # default .
    platforms: [linux/amd64, linux/arm64]              # default both
    build_args:                                        # VERSION is always passed; setting it here is an error
      GO_TAGS: netgo
```

Image vulnerabilities are SCA findings, so the image gate uses `policy.fail_on.sca` and `exceptions` from the same file. An exception for one image finding is addressed by the vulnerability id. A finding's location is `<image> (<platform>) <package>@<version>`, and image names contain `/`, so a path-scoped exception needs `**` globs, for example:

```yaml shipguard-config
exceptions:
  - id: CVE-2026-1234
    path: "**/faridlamaul-portfolio*"
    reason: "Not reachable in this image; waiting for the base image update"
    expires: 2026-12-31
```

## Dry run

`--dry-run` runs shiptag with `--dry-run` and GoReleaser with `release --snapshot --clean --skip=publish`. The image is built and scanned but not pushed or signed. With nothing to release the version is `0.0.0-dryrun`, so a pull request can run it as a check. A dry run never reports `released=true`.

## Outputs

Files in `.shipguard/release/`:

| File | Content |
|---|---|
| `result.json` | `released`, `tag`, `version`, `image`, `image_digest` and the steps with status, reason and `duration_ms`. |
| `summary.md` | The steps table, the released tag, image and digest, and the blocking image findings when the gate blocked. |
| `image-findings.json` | The image findings in the `findings.json` shape; `[]` when there are none. They are never sent to SARIF, GitLab, Bitbucket or annotations. |

On GitHub the command appends `released`, `tag`, `version`, `image` and `image_digest` to `$GITHUB_OUTPUT` and the summary to `$GITHUB_STEP_SUMMARY`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Released, or nothing to release. |
| `1` | The image gate blocked, or a step failed. |
| `2` | Usage or config error: unknown step, invalid `.shipguard.yaml`, `release.image.name` unset without `GITHUB_REPOSITORY`. |

## Re-running a release

A re-run after a failed build finishes the release without creating a second tag: the version step reuses the tag at `HEAD`, the binaries step runs again, and an image already pushed with the same digest is not pushed again.

## Verify a release

```bash
cosign verify ghcr.io/<owner>/<repo>:vX.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/<owner>/<repo>/'

gh attestation verify oci://ghcr.io/<owner>/<repo>:vX.Y.Z --repo <owner>/<repo>
```

For binaries, verify the signature on `checksums.txt` with the `cosign verify-blob` command that matches your GoReleaser `signs:` block, then check the files against it.
