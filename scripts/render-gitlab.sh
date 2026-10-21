#!/bin/sh
# Renders adapters/gitlab/*.yml into an output directory, replacing the single
# placeholder __SHIPGUARD_VERSION__ with v<VERSION>. Templates that download the
# binary also carry __SHIPGUARD_BIN_SHA256_AMD64__ and __SHIPGUARD_BIN_SHA256_ARM64__;
# when any template does, SHIPGUARD_BIN_SHA256_AMD64 and SHIPGUARD_BIN_SHA256_ARM64
# (64 lowercase hex) must be set, else exit 2.
#
# With BITBUCKET_OUT_DIR given, it also renders
# examples/bitbucket/build-test-pipelines.yml there with the same placeholders.
# That file is a release asset, not a GitLab template: it is never written to
# OUT_DIR and its hash is not printed. Without the argument it is not rendered.
#
# Usage: scripts/render-gitlab.sh VERSION [OUT_DIR [BITBUCKET_OUT_DIR]]   (VERSION is X.Y.Z, no "v")
# Prints "<file> sha256-<base64>" for each rendered GitLab file: the value for
# the `integrity:` key of `include: remote`.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 VERSION [OUT_DIR [BITBUCKET_OUT_DIR]]" >&2
  exit 2
fi
version=$1
root=$(cd "$(dirname "$0")/.." && pwd)
out=${2:-$root/dist/gitlab}
bb_out=${3:-}
bb_src=
[ -z "$bb_out" ] || bb_src=$root/examples/bitbucket/build-test-pipelines.yml

case $version in
  *[!0-9.]*|''|.*|*.|*..*) bad=1 ;;
  *) bad=0 ;;
esac
if [ "$bad" = 0 ] && ! printf '%s' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  bad=1
fi
if [ "$bad" = 1 ]; then
  echo "render-gitlab: VERSION must be X.Y.Z without a leading v, got '$version'" >&2
  exit 2
fi

need_hash=0
for src in "$root"/adapters/gitlab/*.yml; do
  if [ -f "$src" ] && grep -q '__SHIPGUARD_BIN_SHA256_' "$src"; then
    need_hash=1
  fi
done
if [ -n "$bb_src" ] && [ -f "$bb_src" ] && grep -q '__SHIPGUARD_BIN_SHA256_' "$bb_src"; then
  need_hash=1
fi
amd64=${SHIPGUARD_BIN_SHA256_AMD64:-}
arm64=${SHIPGUARD_BIN_SHA256_ARM64:-}
if [ "$need_hash" = 1 ]; then
  for pair in "AMD64:$amd64" "ARM64:$arm64"; do
    # The whole value is checked (not line by line): it is spliced into sed.
    v=${pair#*:}
    ok=1
    [ "${#v}" -eq 64 ] || ok=0
    case $v in *[!0123456789abcdef]*) ok=0 ;; esac
    if [ "$ok" = 0 ]; then
      echo "render-gitlab: SHIPGUARD_BIN_SHA256_${pair%%:*} must be 64 lowercase hex characters" >&2
      exit 2
    fi
  done
fi

for src in "$root"/adapters/gitlab/*.yml; do
  if [ -f "$src" ] && ! grep -q '__SHIPGUARD_VERSION__' "$src"; then
    echo "render-gitlab: placeholder missing in $src" >&2
    exit 1
  fi
done

if [ -n "$bb_src" ] && [ -f "$bb_src" ] && ! grep -q '__SHIPGUARD_VERSION__' "$bb_src"; then
  echo "render-gitlab: placeholder missing in $bb_src" >&2
  exit 1
fi

mkdir -p "$out"
rendered=
for src in "$root"/adapters/gitlab/*.yml; do
  [ -f "$src" ] || continue
  dst=$out/$(basename "$src")
  sed -e "s/__SHIPGUARD_VERSION__/v$version/g" \
    -e "s/__SHIPGUARD_BIN_SHA256_AMD64__/$amd64/g" \
    -e "s/__SHIPGUARD_BIN_SHA256_ARM64__/$arm64/g" "$src" > "$dst"
  if grep -Eq '__SHIPGUARD_(VERSION|BIN_SHA256_[A-Z0-9]+)__' "$dst"; then
    echo "render-gitlab: placeholder left in $dst" >&2
    exit 1
  fi
  rendered="$rendered $dst"
done
if [ -z "$rendered" ]; then
  echo "render-gitlab: no templates found in adapters/gitlab" >&2
  exit 1
fi

if [ -n "$bb_src" ] && [ -f "$bb_src" ]; then
  mkdir -p "$bb_out"
  dst=$bb_out/$(basename "$bb_src")
  sed -e "s/__SHIPGUARD_VERSION__/v$version/g" \
    -e "s/__SHIPGUARD_BIN_SHA256_AMD64__/$amd64/g" \
    -e "s/__SHIPGUARD_BIN_SHA256_ARM64__/$arm64/g" "$bb_src" > "$dst"
  if grep -Eq '__SHIPGUARD_(VERSION|BIN_SHA256_[A-Z0-9]+)__' "$dst"; then
    echo "render-gitlab: placeholder left in $dst" >&2
    exit 1
  fi
fi

for dst in $rendered; do
  digest=$(mktemp)
  openssl dgst -sha256 -binary "$dst" > "$digest" || { rm -f "$digest"; echo "render-gitlab: hashing $dst failed" >&2; exit 1; }
  hash=$(openssl base64 -A < "$digest")
  rm -f "$digest"
  if [ "${#hash}" -ne 44 ]; then
    echo "render-gitlab: bad digest for $dst" >&2
    exit 1
  fi
  printf '%s sha256-%s\n' "$dst" "$hash"
done
