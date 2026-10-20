#!/usr/bin/env bash
# Validates every `.shipguard.yaml` snippet in the docs with the real CLI.
#
# A snippet is a fenced block whose info string is `yaml shipguard-config`.
# Each one is written to .shipguard.yaml in a scratch repository next to an
# empty findings.json, and `shipguard gate` must exit 0: it parses the file
# with the same code the scanner uses (unknown keys, bad thresholds, missing
# exception fields and so on all exit 2).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

go build -C "$root" -o "$work/shipguard" ./cmd/shipguard

# Split the snippets into $work/snippets/<doc>-<n>.yaml.
mkdir -p "$work/snippets"
for doc in "$root"/README.md "$root"/docs/*.md; do
  [ -f "$doc" ] || continue
  awk -v out="$work/snippets" -v name="$(basename "$doc" .md)" '
    /^```yaml shipguard-config[[:space:]]*$/ { inblock = 1; n++; file = sprintf("%s/%s-%02d.yaml", out, name, n); printf "" > file; next }
    /^```[[:space:]]*$/ && inblock { inblock = 0; close(file); next }
    inblock { print > file }
  ' "$doc"
done
# Note: the config is checked by the CLI parser only; the JSON Schema is
# covered by internal/policy tests, so it is not re-validated here.

shopt -s nullglob
snippets=("$work"/snippets/*.yaml)
if [ "${#snippets[@]}" -eq 0 ]; then
  echo "docs-check: no shipguard-config snippets found" >&2
  exit 1
fi

failed=0
for snippet in "${snippets[@]}"; do
  repo="$work/repo"
  rm -rf "$repo"
  mkdir -p "$repo/.shipguard"
  cp "$snippet" "$repo/.shipguard.yaml"
  printf '%s\n' '{"schema_version":1,"shipguard_version":"docs-check","scanners":[{"name":"docs-check","category":"secrets","status":"ok","duration_ms":0}],"findings":[]}' \
    > "$repo/.shipguard/findings.json"
  if [ ! -s "$snippet" ] || ! grep -q '[^[:space:]]' "$snippet"; then
    echo "FAIL $(basename "$snippet"): empty snippet"
    failed=1
    continue
  fi
  # Hermetic: no SHIPGUARD_*, CI or step-summary variables leak in.
  if out="$(env -i PATH="$PATH" HOME="$work" "$work/shipguard" gate --dir "$repo" 2>&1)"; then
    echo "ok   $(basename "$snippet")"
  else
    echo "FAIL $(basename "$snippet")"
    printf '%s\n' "$out" | sed 's/^/     /'
    failed=1
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "docs-check: invalid .shipguard.yaml snippet(s)" >&2
  exit 1
fi
echo "docs-check: ${#snippets[@]} snippet(s) valid"
