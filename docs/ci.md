# shipguard ci

`shipguard ci` runs the lint, test and build steps of a project in CI and writes the reports.

## Bitbucket

Bitbucket has no component catalog, so the steps are a snippet you copy.

1. Download `build-test-pipelines.yml` from the [GitHub release](https://github.com/faridlamaul/shipguard/releases) you want to use. The release copy has the version and the SHA-256 of the linux archives filled in; the file under `examples/bitbucket/` is the unrendered source.
2. Copy the steps into your `bitbucket-pipelines.yml`. Keep the `&shipguard-ci` anchor in a step that stays in the file: the other languages reuse it with `*shipguard-ci`.
3. Pick the image of each step (`golang:1.27`, `node:22`, ...) and set `SHIPGUARD_LANGUAGE` and `SHIPGUARD_TOOLCHAIN` to match.

To pin a version, use the file of that release; the script downloads exactly that version and checks its SHA-256 before extracting it. To upgrade, replace the steps with the file of the newer release.

Optional variables, exported before the shared script line: `SHIPGUARD_DIR` (project directory), `SHIPGUARD_CONFIG` (config file) and `SHIPGUARD_CI_STEPS` (space separated `lint`, `test`, `build`; empty runs every configured step).

`-slim` and other minimal images lack `curl`; the step stops with a message. Install it first with `apt-get update && apt-get install -y curl ca-certificates`.

Test reports appear on their own: `shipguard ci` writes `test-results/junit.xml` at the clone root when `BITBUCKET_BUILD_NUMBER` is set, and Bitbucket collects `**/test-results/**/*.xml` into the Tests tab. The summary is printed at the end of the step log, and the step keeps the exit code of `shipguard ci`.
