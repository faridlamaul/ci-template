# Verification results

Results of the questions that had to be answered on the real platforms before the adapters were built.

| # | Status |
|---|---|
| V1 | done: see below |
| V2 | done: see below |
| V3 | done: see below |
| V4 | done: see below |
| V5 | done: opengrep 1.31.0 ships musllinux x86_64 and aarch64; the image is multi-arch on Alpine |
| V6 | done: see below |
| V7 | done: see below |
| B1 | done: see below |
| B2 | done: see below |
| B3 | done: see below |
| B4 | done: see below |

## V1: can a Bitbucket pipe use a GHCR image, pinned by tag and by digest?

**Method.** The private repository `bitbucket.org/faridlamaul/shipguard-test` ran `pipe: docker://ghcr.io/faridlamaul/shipguard:0.0.0-dev` (public dev image, linux/amd64) and, in a custom pipeline, `pipe: docker://ghcr.io/faridlamaul/shipguard@sha256:fb54ae07…` on 2026-10-21.

**Evidence.**
- Pipeline 1 (tag): the runner pulled the image, and the log shows `Digest: sha256:fb54ae07…`.
- Pipeline 2 (digest, `MODE: audit`): successful.

**Result.** A pipe can use a public GHCR image by tag and by digest. No credentials are needed.

**Chosen path.** The fallback (also publishing the image to Docker Hub) is not needed. The docs recommend `docker://ghcr.io/faridlamaul/shipguard:vX.Y.Z@sha256:<digest>`.

## V2: does `git fetch --unshallow` work inside a Bitbucket pipe?

**Method.** The test pipeline sets `clone: depth: 1`, and a custom pipeline sets `SHIPGUARD_EVENT: schedule`, so shipguard has to unshallow before the full-history secrets scan.

**Evidence.**
- Pipeline 3 failed: `fatal: unable to access 'http://bitbucket.org/faridlamaul/shipguard-test/': Failed to connect to localhost:29418 over proxy localhost`. The clone script runs `git config http.${BITBUCKET_GIT_HTTP_ORIGIN}.proxy http://localhost:29418/`, and a pipe runs in its own container, so it cannot reach that address.
- After the fix below, pipeline 7: successful with image `sha256:5e7f35c0…`. The full-history scan finished (5 findings) and the report upload raised no warning.

**Result.** `git fetch --unshallow` works inside a pipe once git's proxy for the origin points at `host.docker.internal:29418`.

**Chosen path.** As a pipe (`BITBUCKET_PIPE_STORAGE_DIR` is set), shipguard passes `-c http.<BITBUCKET_GIT_HTTP_ORIGIN>.proxy=http://host.docker.internal:29418/` to every git call. Users do not need `clone: depth: full`. Pull request pipelines clone the full history anyway (pipeline 6).

## V3: can a pipe post Code Insights through the Pipelines proxy?

**Method.** Atlassian documents `http://host.docker.internal:29418` as the proxy address for custom pipes. A local run of the image as a pipe with the old default `localhost:29418` failed with `proxyconnect tcp: dial tcp [::1]:29418: connect: connection refused`, so the default was changed to `host.docker.internal` when `BITBUCKET_PIPE_STORAGE_DIR` is set.

**Evidence.**
- The pipe container receives `--add-host=host.docker.internal:$BITBUCKET_DOCKER_HOST_INTERNAL` and `BITBUCKET_PIPE_STORAGE_DIR` (pipeline logs).
- Commit `ae1077f` of the test repository carries a `shipguard` report (type SECURITY, reporter shipguard) posted with no token.

**Result.** A pipe can post Code Insights through `http://host.docker.internal:29418` without a token.

**Chosen path.** No app password or access token variable is required. `SHIPGUARD_BITBUCKET_TOKEN` stays optional, and a step image keeps using `localhost:29418`.

## Bitbucket end-to-end

| Pipeline | Event | Outcome |
|---|---|---|
| 1 | push to `main`, `MODE: enforce` | exit 1: 4 blocking, 5 total findings |
| 6 | pull request 1 (adds `cleanup.py` with a command injection) | exit 1: 1 new blocking finding, 5 existing findings do not block |
| 7 | custom `schedule` on a depth-1 clone, `MODE: audit` | exit 0: unshallowed, full-history scan, report posted |

## V4: does osv-scanner support `bun.lock`?

**Method.** I created a directory that contains only a text `bun.lock` (lockfileVersion 1) pinning `lodash@4.17.15`, then ran `osv-scanner scan source -r --format json .` from the image `shipguard:dev` (osv-scanner 2.7.0) on 2026-10-20.

**Evidence.**
- Result source `/src/bun.lock`, type `lockfile`.
- Package `lodash@4.17.15` with 6 vulnerabilities.
- The log line reads "Scanned /src/bun.lock file and found 1 package".

**Result.** osv-scanner 2.7.0 supports `bun.lock`.

**Chosen path.** No change is needed. The docs list `bun.lock` as supported for Node SCA. The legacy binary `bun.lockb` was not tested and is not claimed.

## V6: does `include: remote` from gitlab.com raw work with `inputs` and `integrity`?

**Method.**
- In the public publish project `gitlab.com/faridlamaul/shipguard`, branch `spike/v6` (since deleted), add a template `templates/v6.yml` with a `spec: inputs: greeting` header.
- In the private consumer project `gitlab.com/faridlamaul/shipguard-include-test`, include it with `include: remote: https://gitlab.com/faridlamaul/shipguard/-/raw/spike/v6/templates/v6.yml`, `integrity: sha256-<base64 of the SHA-256 of the raw file>` and `inputs: {greeting: from-include-test}`.

**Evidence.**
- Pipeline 2968541095 on 2026-10-20 succeeded. The job log shows `greeting=from-include-test`, so the input was interpolated.
- The integrity hash computed locally matches the hash of the bytes served by the raw URL.
- `glab ci lint` with a changed integrity value fails: "Remote file … failed integrity check!"

**Result.** `include: remote` from a public gitlab.com raw URL works across projects, with `spec: inputs` interpolation and `integrity` enforcement.

**Chosen path.** The published templates are served from the gitlab.com project. Self-managed users include `https://gitlab.com/faridlamaul/shipguard/-/raw/X.Y.Z/templates/scan.yml` with `integrity` and `inputs`. The release workflow must publish the integrity hash of each template with every release.

## V7: can a called reusable workflow read its own commit SHA?

**Question.** `.github/workflows/scan.yml` must check out `adapters/github` at its own revision. Can a reusable workflow, called from another repository, learn the commit it was loaded from?

**Method.**
- Branch `spike/v7-self-ref` (commit `bb5aa104764183cdef926fdd986afc47265c99af`) added a reusable workflow. It printed `job.workflow_sha`, `job.workflow_ref`, `github.workflow_sha` and `github.workflow_ref`, plus the OIDC claims `job_workflow_ref` and `job_workflow_sha`.
- The private repository `faridlamaul/shipguard-sandbox` called it twice: once by branch (`@spike/v7-self-ref`) and once by SHA.

**Evidence.** Run 39444946922 of `faridlamaul/shipguard-sandbox` on 2026-10-20.

| Expression | Called `@spike/v7-self-ref` | Called `@bb5aa10…` |
|---|---|---|
| `job.workflow_sha` | `bb5aa104…` | `bb5aa104…` |
| `job.workflow_ref` | `faridlamaul/shipguard/.github/workflows/v7-reusable.yml@refs/heads/spike/v7-self-ref` | `…/v7-reusable.yml@bb5aa104…` |
| `github.workflow_sha` / `github.workflow_ref` | the caller's workflow (`shipguard-sandbox/.github/workflows/v7.yml`) | same |
| OIDC `job_workflow_sha` / `job_workflow_ref` | same values as `job.*` | same |

**Result.** `job.workflow_sha` gives the called workflow's own commit, whether the caller references it by branch, tag or SHA. The value is the same as the OIDC claim.

**Chosen path.**
- `scan.yml` checks out `faridlamaul/shipguard` at `${{ job.workflow_sha }}`.
- When `job.workflow_ref` ends in `@refs/tags/vX.Y.Z`, `scan.yml` uses the published image `ghcr.io/faridlamaul/shipguard:vX.Y.Z`.
- Callers do not need `id-token: write`. The OIDC fallback is not needed.
- `github.workflow_*` refers to the caller and must not be used for this purpose.

## B1: do the official language images ship curl, tar and sha256sum?

**Question.** The build-test snippets download and unpack toolchains and checksum them. Which tools are present in the official `golang`, `node`, `python`, `ruby` and `rust` images, and in their `-slim` variants? Is `wget` present?

**Method.** On 2026-10-21 each image was pulled from Docker Hub and probed with `docker run --rm <image> sh -c 'command -v curl; command -v tar; command -v sha256sum; command -v wget'`. The tags are the current stable ones: `golang:1.27`, `node:24`, `python:3.13`, `ruby:3.4`, `rust:1`, and the `-slim` tag of each. The images ran on the host's default platform (Apple Silicon, so linux/arm64). amd64 was not tested. For the slim fallback, `apt-get update && apt-get install -y --no-install-recommends curl ca-certificates` was run in each slim image, then the tools were probed again and an HTTPS request to `https://github.com` was made.

**Evidence.**

| Image | OS | curl | tar | sha256sum | wget |
|---|---|---|---|---|---|
| `golang:1.27` | Debian 13 (trixie) | yes | yes | yes | yes |
| `golang` `-slim` | n/a | no such tag on Docker Hub (only `-alpine`, `-bookworm`, `-trixie`) | | | |
| `node:24` | Debian 12 (bookworm) | yes | yes | yes | yes |
| `node:24-slim` | Debian 12 (bookworm) | no | yes | yes | no |
| `python:3.13` | Debian 13 (trixie) | yes | yes | yes | yes |
| `python:3.13-slim` | Debian 13 (trixie) | no | yes | yes | no |
| `ruby:3.4` | Debian 13 (trixie) | yes | yes | yes | yes |
| `ruby:3.4-slim` | Debian 13 (trixie) | no | yes | yes | no |
| `rust:1` | Debian 13 (trixie) | yes | yes | yes | yes |
| `rust:1-slim` | Debian 13 (trixie) | no | yes | yes | no |

After `apt-get install curl ca-certificates` the four slim images (`node`, `python`, `ruby`, `rust`) had `curl`, and the HTTPS request succeeded.

**Result.** The full Debian images have all four tools. The `-slim` images have `tar` and `sha256sum` but neither `curl` nor `wget`. `golang` has no `-slim` tag, so it is not a gap. `wget` is not present in any slim image, so it cannot be the fallback.

**Chosen path.**
- Full images: use `curl` directly. No install step is needed.
- Slim images: run `apt-get update && apt-get install -y --no-install-recommends curl ca-certificates` first, then use `curl`.
- `golang` has no slim variant. Use `golang:1.27` (Debian trixie, full).

## B2: does GitLab render the JUnit and Cobertura reports and the coverage regex from the component job?

**Method.** The v1.3.0 release published the `ci` component and ran the publish project's tag pipeline, whose `shipguard-ci` job includes the component on the Go pass fixture (2026-10-21).

**Evidence.** Pipeline 2973137959 of gitlab.com/faridlamaul/shipguard succeeded. The `shipguard-ci` job downloaded the v1.3.0 linux binary, checked its SHA-256 and ran `shipguard ci`. The job's coverage reads 100.0 from the `Coverage:` line, the pipeline test report shows 1 test and 0 failures, and the job carries `junit` and `cobertura` report artifacts. The CI/CD Catalog lists the `ci` and `scan` components for 1.3.0.

**Result.** GitLab parses both reports and the coverage regex from a component job. No fallback is needed.

## B3: does Bitbucket pick up the JUnit report?

**Method.** The rendered v1.3.0 snippet ran on branch `test/ci-b3` of `bitbucket.org/faridlamaul/shipguard-test`, with a Go fixture in `goapp/` selected through `SHIPGUARD_DIR`. The default pipeline ran as run #8 on 2026-10-21 on an x86 runner.

**Evidence.**
- The archive SHA-256 check passed and all steps passed. Coverage read 100%.
- The trailing `echo` after `*shipguard-ci` ran, which confirms the shared-shell fix.
- The test-report collector logged "Found 2 test report files" and "total number tests is 2" for one test: it found both `<clone>/test-results/junit.xml` (the copy `shipguard ci` wrote on Bitbucket) and `<project>/.shipguard/ci/test-results/junit.xml`.

**Result.** Bitbucket scans `**/test-results/**/*.xml` including hidden directories, so it finds `.shipguard/ci/test-results/junit.xml` by itself. The clone-root copy only double-counted every test and is removed in this change.

**Chosen path.** `shipguard ci` writes the JUnit only under `.shipguard/ci/test-results/`. No copy and no extra step are needed.

## B4: do the setup actions and the release path work on GitHub-hosted runners?

**Method.** The adapter self-tests on PR #15 ran the composite action (Go pass, Node failing tests) and the reusable workflow (Python) on ubuntu-latest. After v1.3.0, the private sandbox repository faridlamaul/shipguard-sandbox ran `faridlamaul/shipguard/adapters/github/ci@v1.3.0` and `faridlamaul/shipguard/.github/workflows/build-test.yml@v1.3.0` on the Go pass fixture.

**Evidence.** The PR #15 self-test jobs passed. Sandbox run 39644404218 succeeded in both jobs. Each log shows the cosign check of `checksums.txt` ("Verified OK"), then `shipguard_1.3.0_linux_amd64.tar.gz: OK`, and no build from source.

**Result.** setup-go, setup-node and setup-python work on hosted runners, and callers pinned to a version tag run the signed release binary. Ruby (ruby/setup-ruby) and pnpm/yarn through corepack on hosted runners are covered by the e2e images, not yet by a hosted adapter run.

