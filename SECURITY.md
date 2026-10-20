# Security policy

## Supported versions

Security fixes are released for the latest release only. Upgrade to the newest version to receive them.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub: go to the [Security tab](https://github.com/faridlamaul/shipguard/security), choose **Report a vulnerability**, and include:

- the affected version (release, image tag, or commit),
- the platform and CI environment,
- steps to reproduce, and the impact you expect.

You will get an acknowledgement within 7 days. Once the issue is confirmed, a fix is released and the advisory is published with credit to you, unless you prefer to stay anonymous.

## Scope

shipguard is a security gate, so the most valuable reports are ways to get around it or to leak from it:

- a pull request that weakens or skips its own gate (policy, exceptions, scanner ignore files, inline suppressions),
- a finding that should fail the gate but passes, or a scan that passes when it did not run,
- secret values appearing in logs, outputs, summaries, or reports,
- a way for scanned repository content to run code or write outside the workspace,
- problems with the image, its signature, or the release supply chain.

Known limitations are listed in [docs/configuration.md](docs/configuration.md#scanner-native-config-is-ignored) and are not vulnerabilities by themselves.
