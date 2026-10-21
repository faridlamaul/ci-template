#!/usr/bin/env bash
# Resolve the latest release of each pinned scanner, recompute the SHA-256 of
# both Linux assets from the upstream checksums, verify them against the
# downloaded files and rewrite versions.env. Also keeps the CI tool pins in
# internal/ci/tools/ci-tools.env current: only each tool's <TOOL>_VERSION and
# <TOOL>_SHA256_* lines are rewritten (URL templates, manual defaults, comments
# and order stay). The checksums are computed from the downloaded assets
# (HTTPS only) and cross-checked against every upstream source that exists (the digest GitHub
# records and the checksum file the project publishes); at least one source is
# required and all present ones must match. URL templates must stay under
# https://github.com/<owner>/<repo>/releases/download/<tag>/. The newest
# version (semver order) wins; a version below the current pin needs --pin.
# After a write, `go test ./internal/ci/tools/ -run TestLoadEmbedded` must pass
# or the bump fails and ci-tools.env is restored. Idempotent.
#
# Usage: scripts/bump-scanners.sh [--check] [--pin tool=version ...]
#   --check  print the resulting versions.env to stdout, write nothing; exit 1
#            when versions.env or ci-tools.env would change (the ci-tools.env
#            diff goes to stderr), 0 when both are up to date
#   --pin    use this version instead of the latest (tools: gitleaks,
#            opengrep, osv-scanner, trivy, golangci-lint, gotestsum, ruff, uv,
#            cargo-nextest, bun)
# Requires: gh (authenticated), jq, curl, go, and sha256sum or shasum.
#
# Test hooks, honoured only with SHIPGUARD_BUMP_TEST=1: SHIPGUARD_BUMP_DL_DIR
# (read tool assets from this directory instead of downloading) and
# SHIPGUARD_BUMP_VALIDATE (command run instead of go test).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/versions.env"
ci_env="$root/internal/ci/tools/ci-tools.env"
test_mode=0
[ "${SHIPGUARD_BUMP_TEST:-}" = 1 ] && test_mode=1
check=0
pins=""   # space-separated tool=version pairs (bash 3.2 has no associative arrays)

while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1 ;;
    --pin)
      shift
      case "${1:-}" in
        *=*) ;;
        *) echo "--pin wants tool=version" >&2; exit 2 ;;
      esac
      printf '%s\n' "${1#*=}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || { echo "--pin version must be X.Y.Z, got ${1#*=}" >&2; exit 2; }
      pins="$pins $1" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# checksum_from <checksums-file> <asset-name>
checksum_from() { awk -v n="$2" '$2 == n || $2 == "*" n { print $1; exit }' "$1"; }

# release_tag <owner/repo> <tool>
release_tag() {
  local p
  for p in $pins; do
    if [ "${p%%=*}" = "$2" ]; then echo "v${p#*=}"; return; fi
  done
  gh api "repos/$1/releases/latest" --jq .tag_name
}

# verify <owner/repo> <tag> <asset> <expected-sha>: download and compare.
verify() {
  gh release download "$2" --repo "$1" --pattern "$3" --dir "$work" --clobber
  local got
  got="$(sha256 "$work/$3")"
  if [ "$got" != "$4" ]; then
    echo "checksum mismatch for $3: upstream $4, downloaded $got" >&2
    exit 1
  fi
}

lines=()
add() { lines+=("$1=$2"); }

# emit <KEY> <owner/repo> <tag> <asset-amd64> <asset-arm64> <sha-amd64> <sha-arm64>
emit() {
  verify "$2" "$3" "$4" "$6"
  verify "$2" "$3" "$5" "$7"
  add "${1}_VERSION" "${3#v}"
  add "${1}_SHA256_AMD64" "$6"
  add "${1}_SHA256_ARM64" "$7"
}

# checksums <owner/repo> <tag> <checksums-asset>: fetch the upstream file.
checksums() {
  gh release download "$2" --repo "$1" --pattern "$3" --dir "$work" --clobber
}

# gitleaks
repo=gitleaks/gitleaks; tag="$(release_tag $repo gitleaks)"; v="${tag#v}"
checksums $repo "$tag" "gitleaks_${v}_checksums.txt"
a="gitleaks_${v}_linux_x64.tar.gz"; b="gitleaks_${v}_linux_arm64.tar.gz"
emit GITLEAKS $repo "$tag" "$a" "$b" \
  "$(checksum_from "$work/gitleaks_${v}_checksums.txt" "$a")" \
  "$(checksum_from "$work/gitleaks_${v}_checksums.txt" "$b")"

# opengrep publishes no checksums file; use the SHA-256 digest GitHub records
# for each release asset (re-verified against the download).
repo=opengrep/opengrep; tag="$(release_tag $repo opengrep)"
a=opengrep_musllinux_x86; b=opengrep_musllinux_aarch64
emit OPENGREP $repo "$tag" "$a" "$b" \
  "$(gh api "repos/$repo/releases/tags/$tag" --jq ".assets[] | select(.name==\"$a\") | .digest" | sed 's/^sha256://')" \
  "$(gh api "repos/$repo/releases/tags/$tag" --jq ".assets[] | select(.name==\"$b\") | .digest" | sed 's/^sha256://')"

# osv-scanner
repo=google/osv-scanner; tag="$(release_tag $repo osv-scanner)"
checksums $repo "$tag" osv-scanner_SHA256SUMS
a=osv-scanner_linux_amd64; b=osv-scanner_linux_arm64
emit OSV_SCANNER $repo "$tag" "$a" "$b" \
  "$(checksum_from "$work/osv-scanner_SHA256SUMS" "$a")" \
  "$(checksum_from "$work/osv-scanner_SHA256SUMS" "$b")"

# trivy
repo=aquasecurity/trivy; tag="$(release_tag $repo trivy)"; v="${tag#v}"
checksums $repo "$tag" "trivy_${v}_checksums.txt"
a="trivy_${v}_Linux-64bit.tar.gz"; b="trivy_${v}_Linux-ARM64.tar.gz"
emit TRIVY $repo "$tag" "$a" "$b" \
  "$(checksum_from "$work/trivy_${v}_checksums.txt" "$a")" \
  "$(checksum_from "$work/trivy_${v}_checksums.txt" "$b")"

for l in "${lines[@]}"; do
  case "$l" in *=|*=null) echo "missing value: $l" >&2; exit 1 ;; esac
done

# ---- internal/ci/tools/ci-tools.env ----

# ci_tag <owner/repo> <tool> <tag-prefix> <current-version>: the highest stable
# release tag of the form <prefix>X.Y.Z (numeric semver order, not list order;
# prereleases, drafts and other crates' tags are skipped), or the pinned
# version. Without a pin it refuses a version below the current one.
ci_tag() {
  local p tag low
  for p in $pins; do
    if [ "${p%%=*}" = "$2" ]; then echo "$3${p#*=}"; return; fi
  done
  tag="$(gh api "repos/$1/releases?per_page=100" --jq \
    "[.[] | select(.prerelease == false and .draft == false and (.tag_name | test(\"^$3[0-9]+\\\\.[0-9]+\\\\.[0-9]+\$\"))) | {t: .tag_name, v: (.tag_name | ltrimstr(\"$3\") | split(\".\") | map(tonumber))}] | sort_by(.v) | last | .t // empty")"
  if [ -n "$tag" ] && [ "${tag#"$3"}" != "$4" ]; then
    low="$(printf '%s\n%s\n' "${tag#"$3"}" "$4" | sort -V | head -n 1)"
    if [ "$low" = "${tag#"$3"}" ]; then
      echo "$2: latest release ${tag#"$3"} is older than the pinned $4; use --pin $2=<version> to downgrade" >&2
      exit 1
    fi
  fi
  echo "$tag"
}

# envget <KEY>: value of KEY in the current ci-tools.env.
envget() { sed -n "s/^$1=//p" "$ci_env" | head -n 1; }

# fetch <https-url> <dest>
fetch() {
  case "$1" in
    https://*) ;;
    *) echo "refusing non-https download URL: $1" >&2; exit 1 ;;
  esac
  if [ "$test_mode" -eq 1 ] && [ -n "${SHIPGUARD_BUMP_DL_DIR:-}" ]; then
    cp "$SHIPGUARD_BUMP_DL_DIR/$(basename "$1")" "$2"
  else
    curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
  fi
}

# upstream_sum <owner/repo> <tag> <tool> <version> <asset> <dir>: the checksum
# the project itself publishes for <asset>, or nothing when it publishes none.
upstream_sum() {
  local repo=$1 tag=$2 tool=$3 v=$4 asset=$5 dir=$6 name f
  case "$tool" in
    golangci-lint) name="golangci-lint-$v-checksums.txt" ;;
    gotestsum) name="gotestsum-$v-checksums.txt" ;;
    ruff|uv) name="$asset.sha256" ;;
    cargo-nextest) name="${asset%.tar.gz}.sha256" ;;
    bun) name="SHASUMS256.txt" ;;
  esac
  f="$dir/$name"
  gh release download "$tag" --repo "$repo" --pattern "$name" --dir "$dir" --clobber >/dev/null 2>&1 || return 0
  [ -s "$f" ] || return 0
  checksum_from "$f" "$asset"
  # A per-asset file may name the asset differently (or not at all).
  if [ "$(grep -c . "$f")" -eq 1 ] && [ -z "$(checksum_from "$f" "$asset")" ]; then
    awk '{ print $1; exit }' "$f"
  fi
}

ci_lines=()
# ci_tool <KEY> <owner/repo> <tool> <tag-prefix>
ci_tool() {
  local key=$1 repo=$2 tool=$3 prefix=$4 tag v arch upper url asset sha digest up n
  tag="$(ci_tag "$repo" "$tool" "$prefix" "$(envget "${key}_VERSION")")"
  if [ -z "$tag" ]; then echo "$tool: no stable release found" >&2; exit 1; fi
  v="${tag#"$prefix"}"
  ci_lines+=("${key}_VERSION=$v")
  for arch in amd64 arm64; do
    upper="$(echo "$arch" | tr a-z A-Z)"
    url="$(envget "${key}_URL_${upper}")"
    url="${url//\{version\}/$v}"
    case "$url" in
      "https://github.com/$repo/releases/download/$tag/"*) ;;
      *) echo "$tool: ${key}_URL_${upper} must start with https://github.com/$repo/releases/download/$tag/, got $url" >&2; exit 1 ;;
    esac
    asset="$(basename "$url")"
    mkdir -p "$work/ci-$key-$arch"
    fetch "$url" "$work/ci-$key-$arch/$asset"
    sha="$(sha256 "$work/ci-$key-$arch/$asset")"
    digest="$(gh api "repos/$repo/releases/tags/$tag" --jq ".assets[] | select(.name==\"$asset\") | .digest" | sed 's/^sha256://')"
    [ "$digest" = null ] && digest=""
    up="$(upstream_sum "$repo" "$tag" "$tool" "$v" "$asset" "$work/ci-$key-$arch")"
    n=0
    if [ -n "$digest" ]; then
      n=$((n + 1))
      [ "$digest" = "$sha" ] || { echo "checksum mismatch for $asset: GitHub digest $digest, downloaded $sha" >&2; exit 1; }
    fi
    if [ -n "$up" ]; then
      n=$((n + 1))
      [ "$up" = "$sha" ] || { echo "checksum mismatch for $asset: upstream checksum file $up, downloaded $sha" >&2; exit 1; }
    fi
    if [ "$n" -eq 0 ]; then
      echo "$tool: no upstream checksum source (GitHub digest or published checksum file) for $asset; refusing to pin it" >&2
      exit 1
    fi
    ci_lines+=("${key}_SHA256_${upper}=$sha")
  done
}

ci_tool GOLANGCI_LINT golangci/golangci-lint golangci-lint v
ci_tool GOTESTSUM gotestyourself/gotestsum gotestsum v
ci_tool RUFF astral-sh/ruff ruff ""
ci_tool UV astral-sh/uv uv ""
ci_tool CARGO_NEXTEST nextest-rs/nextest cargo-nextest cargo-nextest-
ci_tool BUN oven-sh/bun bun bun-v

# Rewrite only the computed keys, in place.
printf '%s\n' "${ci_lines[@]}" > "$work/ci-new.kv"
awk -F= 'NR == FNR { v[$1] = substr($0, length($1) + 2); next }
  ($1 in v) { print $1 "=" v[$1]; next } { print }' "$work/ci-new.kv" "$ci_env" > "$work/ci-tools.env.new"

body="$(printf '%s\n' "${lines[@]}")"
if [ "$check" -eq 1 ]; then
  printf '%s\n' "$body"
  drift=0
  if diff -u "$out" <(printf '%s\n' "$body") >&2; then
    echo "versions.env is up to date" >&2
  else
    echo "versions.env would change" >&2
    drift=1
  fi
  if diff -u "$ci_env" "$work/ci-tools.env.new" >&2; then
    echo "ci-tools.env is up to date" >&2
  else
    echo "ci-tools.env would change" >&2
    drift=1
  fi
  exit "$drift"
else
  if ! cmp -s "$ci_env" "$work/ci-tools.env.new"; then
    cp "$ci_env" "$work/ci-tools.env.orig"
    cp "$work/ci-tools.env.new" "$ci_env"
    cd "$root"
    if [ "$test_mode" -eq 1 ] && [ -n "${SHIPGUARD_BUMP_VALIDATE:-}" ]; then
      validate=("$SHIPGUARD_BUMP_VALIDATE")
    else
      validate=(go test ./internal/ci/tools/ -run TestLoadEmbedded)
    fi
    if ! "${validate[@]}" >&2; then
      cp "$work/ci-tools.env.orig" "$ci_env"
      echo "ci-tools.env failed validation; restored the previous file" >&2
      exit 1
    fi
  fi
  printf '%s\n' "$body" > "$out"
fi
