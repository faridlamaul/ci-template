#!/bin/sh
# Download the pinned scanner binaries, verify their SHA-256 and install them
# to /usr/local/bin. Usage: install-scanners.sh <amd64|arm64>
set -eu

arch="${1:?usage: install-scanners.sh <amd64|arm64>}"
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../versions.env
. "$here/../versions.env"

case "$arch" in
  amd64)
    gitleaks_asset="linux_x64"; gitleaks_sha="$GITLEAKS_SHA256_AMD64"
    opengrep_asset="musllinux_x86"; opengrep_sha="$OPENGREP_SHA256_AMD64"
    osv_asset="linux_amd64"; osv_sha="$OSV_SCANNER_SHA256_AMD64"
    trivy_asset="Linux-64bit"; trivy_sha="$TRIVY_SHA256_AMD64"
    ;;
  arm64)
    gitleaks_asset="linux_arm64"; gitleaks_sha="$GITLEAKS_SHA256_ARM64"
    opengrep_asset="musllinux_aarch64"; opengrep_sha="$OPENGREP_SHA256_ARM64"
    osv_asset="linux_arm64"; osv_sha="$OSV_SCANNER_SHA256_ARM64"
    trivy_asset="Linux-ARM64"; trivy_sha="$TRIVY_SHA256_ARM64"
    ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# fetch <url> <sha256> <output-name>: download into $work and verify.
fetch() {
  curl -fsSL --retry 3 -o "$work/$3" "$1"
  echo "$2  $work/$3" | sha256sum -c -
}

gl="gitleaks_${GITLEAKS_VERSION}_${gitleaks_asset}.tar.gz"
fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gl}" "$gitleaks_sha" "$gl"
tar -xzf "$work/$gl" -C /usr/local/bin gitleaks

fetch "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_${opengrep_asset}" "$opengrep_sha" opengrep
install -m 0755 "$work/opengrep" /usr/local/bin/opengrep

fetch "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${osv_asset}" "$osv_sha" osv-scanner
install -m 0755 "$work/osv-scanner" /usr/local/bin/osv-scanner

tv="trivy_${TRIVY_VERSION}_${trivy_asset}.tar.gz"
fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tv}" "$trivy_sha" "$tv"
tar -xzf "$work/$tv" -C /usr/local/bin trivy
