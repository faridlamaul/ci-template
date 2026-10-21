#!/bin/sh
# Lints the rendered GitLab templates through the gitlab.com CI lint API.
# Usage: scripts/gitlab-lint.sh PROJECT_ID RENDERED_DIR
# Needs an authenticated glab and jq.
set -eu
project=$1
dir=$2
root=$(cd "$(dirname "$0")/.." && pwd)

lint() { # lint FILE
  body=$(jq -Rs '{content: ., include_jobs: true}' < "$1")
  resp=$(printf '%s' "$body" | glab api -X POST "projects/$project/ci/lint" \
    -H 'Content-Type: application/json' --input -)
  valid=$(printf '%s' "$resp" | jq -r '.valid')
  echo "$1: valid: $valid"
  printf '%s' "$resp" | jq -r '(.errors // [])[], (.warnings // [])[]' | sed 's/^/  /'
  [ "$valid" = "true" ]
}

for f in "$dir"/*.yml; do
  # ci.yml has required inputs; it is linted below as part of a consumer file.
  if [ "$(basename "$f")" = ci.yml ]; then
    if grep -q '__SHIPGUARD_' "$f"; then echo "$f: placeholder left" >&2; exit 1; fi
    continue
  fi
  if grep -q '__SHIPGUARD_VERSION__' "$f"; then
    echo "$f: placeholder left" >&2
    exit 1
  fi
  lint "$f"
done

# The smoke pipeline includes templates/scan.yml locally, which exists only in
# the publish project. Lint a combined file instead: the rendered template
# (mode default set to audit, as the smoke test passes) followed by the smoke
# file without its include block.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
combined=$tmp/combined.yml
sed 's/^\(      default: \)""$/\1audit/' "$dir/scan.yml" > "$combined"
awk '/^include:/ {skip=1; next} skip && /^[[:space:]]/ {next} {skip=0; print}' \
  "$root/adapters/gitlab/test/.gitlab-ci.yml" >> "$combined"
grep -q 'default: audit' "$combined" || { echo "combined smoke file: mode default not set" >&2; exit 1; }
if grep -q '^include:' "$combined"; then echo "combined smoke file: include left" >&2; exit 1; fi
lint "$combined"

# The component smoke pipeline: the rendered ci.yml with the inputs that
# test/ci.gitlab-ci.yml passes (spec header dropped), followed by the smoke file
# without its include block.
ci_combined=$tmp/ci-combined.yml
awk 'body {print} /^---$/ {body=1}' "$dir/ci.yml" |
  sed -e 's/\$\[\[ inputs\.language \]\]/golang/g' \
    -e 's/\$\[\[ inputs\.version \]\]/1.27/g' \
    -e 's/\$\[\[ inputs\.registry \]\]//g' \
    -e 's|\$\[\[ inputs\.dir \]\]|test/fixtures/go-pass|g' \
    -e 's/\$\[\[ inputs\.steps \]\]//g' \
    -e 's/\$\[\[ inputs\.config \]\]/.shipguard.yaml/g' \
    -e 's/\$\[\[ inputs\.stage \]\]/test/g' > "$ci_combined"
awk '/^include:/ {skip=1; next} skip && /^[[:space:]]/ {next} {skip=0; print}' \
  "$root/adapters/gitlab/test/ci.gitlab-ci.yml" >> "$ci_combined"
if grep -q 'inputs\.' "$ci_combined"; then echo "ci combined file: input left" >&2; exit 1; fi
if grep -q '^include:' "$ci_combined"; then echo "ci combined file: include left" >&2; exit 1; fi
lint "$ci_combined"
