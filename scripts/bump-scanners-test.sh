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

mkdir -p "$work/bin" "$work/repo/scripts" "$work/repo/internal/ci/tools" "$work/dl"
cp "$root/scripts/bump-scanners.sh" "$work/repo/scripts/"
ci_env="$work/repo/internal/ci/tools/ci-tools.env"
cp "$root/internal/ci/tools/ci-tools.env" "$ci_env"
# Start every tool below the fake release (1.0.0) so the bump is an upgrade.
sed -E 's/^(GOLANGCI_LINT|GOTESTSUM|RUFF|UV|CARGO_NEXTEST|BUN)_VERSION=.*/\1_VERSION=0.0.1/' "$ci_env" > "$work/ci-seed.env"
cp "$work/ci-seed.env" "$ci_env"
cp "$ci_env" "$work/ci-original.env"

# Tool assets are fetched with curl (https only); the script reads them from
# this directory instead, which it only does when SHIPGUARD_BUMP_TEST=1.
grep '_URL_' "$work/ci-original.env" | cut -d= -f2- | sed 's/{version}/1.0.0/g' | while read -r u; do
  n=$(basename "$u")
  printf 'asset:%s' "$n" > "$work/dl/$n"
done

# Stand-in for `go test ./internal/ci/tools/ -run TestLoadEmbedded`.
cat > "$work/validate.sh" <<'VEOF'
#!/bin/sh
[ "${FAKE_VALIDATE_FAIL:-}" != 1 ]
VEOF
chmod +x "$work/validate.sh"

# Fake gh: every release is v1.0.0, an asset's content is "asset:<name>" and
# the checksums files and asset digests are computed from that content.
cat > "$work/bin/gh" <<'EOF'
#!/bin/sh
set -eu
sum() { printf 'asset:%s' "$1" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1; }
case "$1 $2" in
  "api repos/"*/releases/latest) echo v1.0.0 ;;
  "api repos/"*"/releases?"*)
    case "$2" in
      *nextest*) p=cargo-nextest- ;; *bun*) p=bun-v ;; *astral-sh*) p= ;; *) p=v ;;
    esac
    cat <<JSON | jq -r "$4"
[{"tag_name":"${p}2.0.0-rc1","prerelease":true,"draft":false},
 {"tag_name":"nextest-runner-9.9.9","prerelease":false,"draft":false},
 {"tag_name":"${p}3.0.0","prerelease":false,"draft":true},
 {"tag_name":"${p}0.9.5","prerelease":false,"draft":false},
 {"tag_name":"${p}1.0.0","prerelease":false,"draft":false},
 {"tag_name":"${p}0.9.0","prerelease":false,"draft":false}]
JSON
    ;;
  "api repos/"*/releases/tags/*)
    name=$(printf '%s' "$4" | sed 's/.*\.name=="\([^"]*\)".*/\1/')
    case "$name" in opengrep*) ;; *) [ "${FAKE_NO_DIGEST:-}" = 1 ] && exit 0 ;; esac
    case "$name" in
      "${FAKE_BAD_DIGEST:-@@}") echo "sha256:$(sum bad-digest)" ;;
      *) echo "sha256:$(sum "$name")" ;;
    esac ;;
  "release download")
    pattern=$7 dir=$9
    case "$pattern" in
      "${FAKE_BAD_SUMFILE:-@@}") echo "$(sum bad-sumfile)  ${pattern%.sha256}" > "$dir/$pattern" ;;
      golangci-lint-*-checksums.txt|gotestsum-*-checksums.txt|SHASUMS256.txt)
        [ "${FAKE_NO_SUMFILES:-}" != 1 ] || exit 1
        for n in golangci-lint-1.0.0-linux-amd64.tar.gz golangci-lint-1.0.0-linux-arm64.tar.gz \
          gotestsum_1.0.0_linux_amd64.tar.gz gotestsum_1.0.0_linux_arm64.tar.gz \
          bun-linux-x64-musl.zip bun-linux-aarch64-musl.zip; do
          echo "$(sum "$n")  $n"
        done > "$dir/$pattern" ;;
      ruff-*.sha256|uv-*.sha256|cargo-nextest-*.sha256)
        [ "${FAKE_NO_SUMFILES:-}" != 1 ] || exit 1
        n=${pattern%.sha256}
        case "$n" in cargo-nextest-*) n=$n.tar.gz ;; esac
        echo "$(sum "$n") *$n" > "$dir/$pattern" ;;
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

bump() {
  PATH="$work/bin:$PATH" SHIPGUARD_BUMP_TEST=1 SHIPGUARD_BUMP_DL_DIR="$work/dl" \
    SHIPGUARD_BUMP_VALIDATE="$work/validate.sh" "$work/repo/scripts/bump-scanners.sh" "$@"
}
sum_of() { printf 'asset:%s' "$1" | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1; }

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

# The first write also proves the highest tag wins over list order (0.9.5 and
# 0.9.0 are listed around 1.0.0).

# ---- ci-tools.env ----

# The first write bumped every tool and both of its checksums.
for k in GOLANGCI_LINT GOTESTSUM RUFF UV CARGO_NEXTEST BUN; do
  grep -q "^${k}_VERSION=1.0.0$" "$ci_env" || fail "${k}_VERSION not bumped to 1.0.0 (prereleases, drafts and other crates must be skipped)"
done
want_sha=$(sum_of ruff-x86_64-unknown-linux-musl.tar.gz)
if grep -q "^RUFF_SHA256_AMD64=$want_sha$" "$ci_env"; then pass "ci-tools.env checksum is the SHA-256 of the downloaded asset"
else fail "RUFF_SHA256_AMD64 is not the SHA-256 of the downloaded asset"; fi

# Only <TOOL>_VERSION and <TOOL>_SHA256_* of the six tools may differ
# (templates, manual defaults, comments and order stay).
if diff "$work/ci-original.env" "$ci_env" | grep '^[<>]' \
  | grep -Ev '^[<>] (GOLANGCI_LINT|GOTESTSUM|RUFF|UV|CARGO_NEXTEST|BUN)_(VERSION|SHA256_AMD64|SHA256_ARM64)=' | grep . >/dev/null; then
  fail "ci-tools.env changed lines other than tool versions and checksums"
else pass "ci-tools.env keeps templates, defaults, comments and order"
fi
if [ "$(grep -c '' "$ci_env")" -eq "$(grep -c '' "$work/ci-original.env")" ]; then pass "ci-tools.env keeps its line count"
else fail "ci-tools.env line count changed"; fi

cp "$work/expected.env" "$work/repo/versions.env"
# --check covers ci-tools.env: up to date is 0, a stale pin is 1 and writes nothing.
if bump --check > /dev/null 2> "$work/check.err"; then pass "--check exits 0 when ci-tools.env is up to date"
else fail "--check exited $? with up-to-date files: $(cat "$work/check.err")"; fi
cp "$ci_env" "$work/ci-good.env"
sed 's/^BUN_VERSION=.*/BUN_VERSION=0.0.1/' "$work/ci-good.env" > "$ci_env"
cp "$ci_env" "$work/ci-stale.env"
cp "$work/expected.env" "$work/repo/versions.env"
code=0
bump --check > /dev/null 2> "$work/check.err" || code=$?
if [ "$code" -eq 1 ]; then pass "--check exits 1 when ci-tools.env would change"
else fail "--check exited $code when ci-tools.env would change (want 1)"; fi
if cmp -s "$ci_env" "$work/ci-stale.env"; then pass "--check leaves ci-tools.env alone"
else fail "--check modified ci-tools.env"; fi

# --pin selects a tool version; the script adds the tag prefix.
if bump --pin bun=0.9.0 > "$work/pin.out" 2>&1 && grep -q '^BUN_VERSION=0.9.0$' "$ci_env"; then pass "--pin bun=0.9.0 writes BUN_VERSION=0.9.0"
else fail "--pin bun=0.9.0 not applied: $(cat "$work/pin.out")"; fi
cp "$work/ci-stale.env" "$ci_env"
code=0
bump --pin golangci-lint=0.9.0 > "$work/pin.out" 2>&1 || code=$?
if [ "$code" -ne 0 ] && cmp -s "$ci_env" "$work/ci-stale.env"; then pass "--pin of a version without downloadable assets fails"
else fail "--pin golangci-lint=0.9.0 succeeded without assets"; fi

# A digest that disagrees with the download fails and writes nothing.
code=0
( export FAKE_BAD_DIGEST=uv-x86_64-unknown-linux-musl.tar.gz; bump > "$work/bad.out" 2>&1 ) || code=$?
if [ "$code" -ne 0 ] && grep -q 'checksum mismatch' "$work/bad.out" && cmp -s "$ci_env" "$work/ci-stale.env"; then
  pass "a digest mismatch fails without writing"
else fail "digest mismatch not rejected (exit $code): $(cat "$work/bad.out")"; fi

# No digest and no checksum file: the bump fails instead of pinning unverified.
code=0
( export FAKE_NO_DIGEST=1; export FAKE_NO_SUMFILES=1; bump > "$work/nosrc.out" 2>&1 ) || code=$?
if [ "$code" -ne 0 ] && grep -q 'no upstream checksum source' "$work/nosrc.out" && cmp -s "$ci_env" "$work/ci-stale.env"; then
  pass "no checksum source fails closed"
else fail "missing checksum sources not rejected (exit $code): $(cat "$work/nosrc.out")"; fi

# One source is enough: the checksum file alone, and the digest alone.
cp "$work/ci-good.env" "$ci_env"
if ( export FAKE_NO_DIGEST=1; bump --check ) > /dev/null 2> "$work/one.err"; then pass "checksum file alone is accepted"
else fail "checksum file alone rejected: $(head -c 600 "$work/one.err")"; fi
cp "$work/ci-good.env" "$ci_env"
if ( export FAKE_NO_SUMFILES=1; bump --check ) > /dev/null 2>&1; then pass "GitHub digest alone is accepted"
else fail "GitHub digest alone rejected"; fi
cp "$work/ci-stale.env" "$ci_env"

# A wrong checksum in the published checksum file fails, per file format.
for f in golangci-lint-1.0.0-checksums.txt gotestsum-1.0.0-checksums.txt SHASUMS256.txt \
  ruff-x86_64-unknown-linux-musl.tar.gz.sha256 cargo-nextest-1.0.0-x86_64-unknown-linux-musl.sha256; do
  code=0
  ( export FAKE_BAD_SUMFILE=$f; bump > "$work/badsum.out" 2>&1 ) || code=$?
  if [ "$code" -ne 0 ] && grep -q 'upstream checksum file' "$work/badsum.out" && cmp -s "$ci_env" "$work/ci-stale.env"; then
    pass "mismatch in $f fails"
  else fail "mismatch in $f not rejected (exit $code): $(cat "$work/badsum.out")"; fi
done

# A URL template outside the project's release path is refused.
sed 's#^UV_URL_ARM64=https://github.com/astral-sh/uv/#UV_URL_ARM64=https://github.com/someone-else/uv/#' "$work/ci-stale.env" > "$ci_env"
code=0
bump > "$work/url.out" 2>&1 || code=$?
if [ "$code" -ne 0 ] && grep -q 'UV_URL_ARM64 must start with https://github.com/astral-sh/uv/releases/download/' "$work/url.out"; then
  pass "URL outside the release path is refused"
else fail "foreign URL accepted (exit $code): $(cat "$work/url.out")"; fi
cp "$work/ci-stale.env" "$ci_env"

# A latest release below the current pin is refused, unless --pin is used.
sed 's/^BUN_VERSION=.*/BUN_VERSION=2.0.0/' "$work/ci-stale.env" > "$ci_env"
cp "$ci_env" "$work/ci-newer.env"
code=0
bump > "$work/down.out" 2>&1 || code=$?
if [ "$code" -ne 0 ] && grep -q 'older than the pinned' "$work/down.out" && cmp -s "$ci_env" "$work/ci-newer.env"; then
  pass "a downgrade is refused"
else fail "downgrade not refused (exit $code)"; fi
if bump --pin bun=1.0.0 > /dev/null 2>&1 && grep -q '^BUN_VERSION=1.0.0$' "$ci_env"; then pass "--pin may downgrade"
else fail "--pin bun=1.0.0 did not downgrade"; fi
cp "$work/ci-stale.env" "$ci_env"

# --pin values must be X.Y.Z.
for bad in bun=v1.0.0 bun=1.0 'bun=1.0.0;x' bun; do
  code=0
  bump --pin "$bad" > /dev/null 2>&1 || code=$?
  [ "$code" -eq 2 ] && pass "--pin $bad is rejected" || fail "--pin $bad exited $code (want 2)"
done

# A failing validation restores the original file and fails the bump.
code=0
( export FAKE_VALIDATE_FAIL=1; bump > "$work/val.out" 2>&1 ) || code=$?
if [ "$code" -ne 0 ] && cmp -s "$ci_env" "$work/ci-stale.env"; then pass "failed validation restores ci-tools.env"
else fail "failed validation not handled (exit $code)"; fi

# Non-https templates are refused.
sed 's#^UV_URL_AMD64=https://#UV_URL_AMD64=http://#' "$work/ci-stale.env" > "$ci_env"
code=0
bump > "$work/http.out" 2>&1 || code=$?
if [ "$code" -ne 0 ] && grep -q 'https' "$work/http.out"; then pass "non-https tool URL is refused"
else fail "non-https tool URL accepted (exit $code)"; fi

if [ "$fails" -ne 0 ]; then echo "$fails failure(s)" >&2; exit 1; fi
echo "all bump-scanners tests passed"
