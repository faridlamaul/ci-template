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

`shipguard.<lang>.<rule-name>`, for example `shipguard.python.unsafe-deserialization`.
Every rule has `id`, `languages`, `severity`, an actionable `message`, and
`metadata` with `category: security`, `cwe` and `confidence` (HIGH, MEDIUM, LOW).

## Severity guidance

| opengrep | shipguard | Use for |
| --- | --- | --- |
| ERROR | high (blocks by default) | Directly exploitable patterns with user-controlled input, or clearly dangerous configuration (TLS verification disabled, `shell=True` with variables, request data passed to `pickle` or an unsafe yaml loader, `eval` of non-literals) |
| WARNING | medium | Weak crypto or hashing, probable issues, hard-coded credentials, source-agnostic deserialization such as `pickle.load` of a local file |
| INFO | low | Constructs that deserve review (for example `unsafe` blocks) |

Prefer `pattern-not` for constants and literals to keep false positives low.
SSRF, path traversal and SQL rules focus on the URL, path or query argument, so
tainted request bodies or parameters do not trigger them.

Assumptions:

- JavaScript: `yaml.load` is treated as safe, which holds for js-yaml 4. On
  js-yaml 3 `yaml.load` is unsafe by default; upgrade the library.
- Ruby: `YAML.load` and `Psych.load` are safe by default since Ruby 3.1
  (Psych 4) and are not flagged. `unsafe-deserialization` (WARNING) flags
  `unsafe_load`, `Marshal.load` and Oj object mode from any source;
  `unsafe-deserialization-request` (ERROR) requires request data to reach them.
- JavaScript: `node-serialize` `unserialize` is always ERROR because it has no
  safe use.
- Python: `unsafe-deserialization` (WARNING) flags any use;
  `unsafe-deserialization-request` (ERROR) requires request data to reach the
  call.

## Tests

Each rule has a target file with `ruleid:` and `ok:` annotations on the line
above the code. Run the whole suite with:

```
opengrep test rules/
```

Test targets are intentionally vulnerable and contain fake credentials such as
`changeme-not-a-secret`. They are examples for the rule tests, not application
code, and `rules/go.mod` keeps the Go targets out of the main module's build.
