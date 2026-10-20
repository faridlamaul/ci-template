# shipguard built-in rules

Curated opengrep rules that shipguard loads with `opengrep scan --config <dir>`
(`/opt/shipguard/rules` in the container image).

## Provenance and license

These rules are original work written for shipguard and released under the MIT
license (see `LICENSE`). They were written from knowledge of the vulnerable
APIs and were not copied, adapted or paraphrased from semgrep/semgrep-rules,
opengrep/opengrep-rules or any other third-party ruleset. Do not contribute
rules derived from those sources: the Semgrep Rules License does not allow
redistribution.

## Layout

```
rules/<lang>/<rule-name>.yaml   one rule per file
rules/<lang>/<rule-name>.<ext>  test target next to the rule
```

Language directories: `go`, `javascript` (covers TypeScript), `python`,
`ruby`, `rust`.

## Rule id convention

`shipguard.<lang>.<rule-name>`, for example `shipguard.python.pickle-load`.
Every rule has `id`, `languages`, `severity`, an actionable `message`, and
`metadata` with `category: security`, `cwe` and `confidence` (HIGH, MEDIUM, LOW).

## Severity guidance

| opengrep | shipguard | Use for |
| --- | --- | --- |
| ERROR | high (blocks by default) | Directly exploitable patterns with user-controlled input, or clearly dangerous configuration (TLS verification disabled, `shell=True` with variables, `pickle` or `yaml.load` on input, `eval` of non-literals) |
| WARNING | medium | Weak crypto or hashing, probable issues, hard-coded credentials |
| INFO | low | Constructs that deserve review (for example `unsafe` blocks) |

Prefer `pattern-not` for constants and literals to keep false positives low.

## Tests

Each rule has a target file with `ruleid:` and `ok:` annotations on the line
above the code. Run the whole suite with:

```
opengrep test rules/
```

Test targets contain deliberately vulnerable code and fake credentials such as
`changeme-not-a-secret`. Scan configuration for this repository excludes
`rules/**`.
