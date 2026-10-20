# Verification spike (Task 0)

Results of the verification items in spec §10 and §12.

| # | Status |
|---|---|
| V1 | pending (Bitbucket access) |
| V2 | pending (Bitbucket access) |
| V3 | pending (Bitbucket access) |
| V4 | pending |
| V5 | done in Task 16: opengrep 1.31.0 ships musllinux x86_64 and aarch64; the image is multi-arch on Alpine |
| V6 | pending (gitlab.com test project) |
| V7 | done: see below |

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
- Callers do not need `id-token: write`. The OIDC fallback in spec §12 A5 is not needed.
- `github.workflow_*` refers to the caller and must not be used for this purpose.
