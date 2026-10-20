#!/bin/sh
# Renders adapters/gitlab/*.yml into an output directory, replacing the single
# placeholder __SHIPGUARD_VERSION__ with v<VERSION>.
#
# Usage: scripts/render-gitlab.sh VERSION [OUT_DIR]   (VERSION is X.Y.Z, no "v")
# Prints "<file> sha256-<base64>" for each rendered file: the value for the
# `integrity:` key of `include: remote`.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 VERSION [OUT_DIR]" >&2
  exit 2
fi
version=$1
root=$(cd "$(dirname "$0")/.." && pwd)
out=${2:-$root/dist/gitlab}

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

for src in "$root"/adapters/gitlab/*.yml; do
  if [ -f "$src" ] && ! grep -q '__SHIPGUARD_VERSION__' "$src"; then
    echo "render-gitlab: placeholder missing in $src" >&2
    exit 1
  fi
done

mkdir -p "$out"
rendered=
for src in "$root"/adapters/gitlab/*.yml; do
  [ -f "$src" ] || continue
  dst=$out/$(basename "$src")
  sed "s/__SHIPGUARD_VERSION__/v$version/g" "$src" > "$dst"
  if grep -q '__SHIPGUARD_VERSION__' "$dst"; then
    echo "render-gitlab: placeholder left in $dst" >&2
    exit 1
  fi
  rendered="$rendered $dst"
done
if [ -z "$rendered" ]; then
  echo "render-gitlab: no templates found in adapters/gitlab" >&2
  exit 1
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
