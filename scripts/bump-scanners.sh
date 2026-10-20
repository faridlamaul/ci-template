#!/usr/bin/env bash
# Resolve the latest release of each pinned scanner, recompute the SHA-256 of
# both Linux assets from the upstream checksums, verify them against the
# downloaded files and rewrite versions.env. Idempotent: no change, no diff.
#
# Usage: scripts/bump-scanners.sh [--check] [--pin tool=version ...]
#   --check  print the resulting versions.env to stdout, write nothing
#   --pin    use this version instead of the latest (tools: gitleaks,
#            opengrep, osv-scanner, trivy)
# Requires: gh (authenticated), curl, and sha256sum or shasum.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/versions.env"
check=0
pins=""   # space-separated tool=version pairs (bash 3.2 has no associative arrays)

while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1 ;;
    --pin) shift; pins="$pins $1" ;;
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

body="$(printf '%s\n' "${lines[@]}")"
if [ "$check" -eq 1 ]; then
  printf '%s\n' "$body"
  if diff -u "$out" <(printf '%s\n' "$body") >&2; then echo "versions.env is up to date" >&2; fi
else
  printf '%s\n' "$body" > "$out"
fi
