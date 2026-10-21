#!/bin/sh
# Tests scripts/bump-scanners.sh against a fake gh on PATH (no network).
# Usage: scripts/bump-scanners-test.sh
#
# The script runs from a copy of the repository layout in a temp directory, so
# the real versions.env is never touched.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

mkdir -p "$work/bin" "$work/repo/scripts"
cp "$root/scripts/bump-scanners.sh" "$work/repo/scripts/"

# Fake gh: every release is v1.0.0, an asset's content is "asset:<name>" and
# the checksums files and asset digests are computed from that content.
cat > "$work/bin/gh" <<'EOF'
#!/bin/sh
set -eu
sum() { printf 'asset:%s' "$1" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1; }
case "$1 $2" in
  "api repos/"*/releases/latest) echo v1.0.0 ;;
  "api repos/"*/releases/tags/*)
    name=$(printf '%s' "$4" | sed 's/.*\.name=="\([^"]*\)".*/\1/')
    echo "sha256:$(sum "$name")" ;;
  "release download")
    pattern=$7 dir=$9
    case "$pattern" in
      *checksums.txt|*SHA256SUMS)
        for n in gitleaks_1.0.0_linux_x64.tar.gz gitleaks_1.0.0_linux_arm64.tar.gz \
          osv-scanner_linux_amd64 osv-scanner_linux_arm64 \
          trivy_1.0.0_Linux-64bit.tar.gz trivy_1.0.0_Linux-ARM64.tar.gz; do
          echo "$(sum "$n")  $n"
        done > "$dir/$pattern" ;;
      *) printf 'asset:%s' "$pattern" > "$dir/$pattern" ;;
    esac ;;
  *) echo "fake gh: unexpected call: $*" >&2; exit 3 ;;
esac
EOF
chmod +x "$work/bin/gh"

bump() { PATH="$work/bin:$PATH" "$work/repo/scripts/bump-scanners.sh" "$@"; }

# A write produces versions.env with every key.
if bump > "$work/write.out" 2>&1 && grep -q '^TRIVY_VERSION=1.0.0$' "$work/repo/versions.env"; then
  pass "write rewrites versions.env"
else
  fail "write did not produce versions.env: $(cat "$work/write.out")"
fi
cp "$work/repo/versions.env" "$work/expected.env"

# --check on an up-to-date file exits 0 and writes nothing.
if bump --check > "$work/check.out" 2> "$work/check.err"; then
  pass "--check exits 0 when up to date"
else
  fail "--check exited $? when up to date: $(cat "$work/check.err")"
fi

# --check on a stale file exits 1 and leaves the file alone.
sed 's/^TRIVY_VERSION=.*/TRIVY_VERSION=0.0.1/' "$work/expected.env" > "$work/repo/versions.env"
cp "$work/repo/versions.env" "$work/stale.env"
code=0
bump --check > "$work/check.out" 2> "$work/check.err" || code=$?
if [ "$code" -eq 1 ]; then pass "--check exits 1 when versions.env would change"
else fail "--check exited $code when versions.env would change (want 1)"; fi
if cmp -s "$work/repo/versions.env" "$work/stale.env"; then pass "--check writes nothing"
else fail "--check modified versions.env"; fi
if cmp -s "$work/check.out" "$work/expected.env"; then pass "--check prints the resulting versions.env"
else fail "--check stdout is not the resulting versions.env"; fi

if [ "$fails" -ne 0 ]; then echo "$fails failure(s)" >&2; exit 1; fi
echo "all bump-scanners tests passed"
