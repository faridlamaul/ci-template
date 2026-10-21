#!/bin/sh
# Tests scripts/publish-gitlab.sh against local bare repositories.
# Usage: scripts/publish-gitlab-test.sh   (also: make publish-test)
#
# The publish script accepts a file:// remote only with SHIPGUARD_PUBLISH_TEST=1,
# so this test never talks to gitlab.com.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
# ci.yml carries the archive hashes; any 64 lowercase hex digits render.
export SHIPGUARD_BIN_SHA256_AMD64=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export SHIPGUARD_BIN_SHA256_ARM64=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A fake token. It must never show up in the output or in any git config.
token=shipguard-test-sentinel-0123456789
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

fails=0
fail() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }
pass() { echo "ok: $*"; }

# new_remote NAME: a bare repo whose main holds a stale template and an
# unrelated file, the way the gitlab.com project looks after an older release.
new_remote() {
  git init -q --bare -b main "$work/$1.git"
  seed=$work/$1-seed
  git init -q -b main "$seed"
  mkdir -p "$seed/templates"
  echo old > "$seed/templates/old.yml"
  echo keep > "$seed/other.txt"
  git -C "$seed" add -A
  git -C "$seed" commit -q -m seed
  git -C "$seed" push -q "$work/$1.git" main
}

# publish NAME VERSION OUT: runs the publish script; returns its exit code.
publish() {
  rm -rf "$work/dist-$2"
  "$root/scripts/render-gitlab.sh" "$2" "$work/dist-$2" > "$work/integrity-$2.txt"
  set +e
  env VERSION="$2" GITLAB_PUBLISH_TOKEN="$token" SHIPGUARD_PUBLISH_TEST=1 \
    PUBLISH_BASE_URL=file:/// PUBLISH_REPO="${work#/}/$1.git" \
    RENDERED_DIR="$work/dist-$2" INTEGRITY_FILE="$work/integrity-$2.txt" \
    "$root/scripts/publish-gitlab.sh" > "$3" 2>&1
  rc=$?
  set -e
  return "$rc"
}

no_token() { # no_token FILE...
  if grep -rqF "$token" "$@"; then fail "token found in $*"; else pass "token absent from $(basename "$1")"; fi
}

# 1. A first publish puts every file in place and creates an annotated tag.
new_remote main
if publish main 1.2.3 "$work/out1"; then pass "publish 1.2.3 exits 0"; else fail "publish 1.2.3 exited $?: $(cat "$work/out1")"; fi
check=$work/check
git clone -q --branch 1.2.3 "$work/main.git" "$check" 2> /dev/null || { fail "tag 1.2.3 not found on the remote"; exit 1; }
if [ "$(git -C "$check" cat-file -t 1.2.3)" = tag ]; then pass "tag 1.2.3 is annotated"; else fail "tag 1.2.3 is not annotated"; fi
if [ "$(git -C "$check" tag -l --format='%(contents:subject)' 1.2.3)" = "release 1.2.3" ]; then pass "tag message"; else fail "tag message"; fi
if [ "$(git -C "$check" log -1 --format='%s|%an <%ae>')" = "release 1.2.3|shipguard-release <noreply@github.com>" ]; then pass "commit subject and author"; else fail "commit: $(git -C "$check" log -1 --format='%s|%an <%ae>')"; fi
if [ "$(git -C "$check" rev-parse "1.2.3^{commit}")" = "$(git -C "$check" rev-parse origin/main)" ]; then pass "main points at the tag"; else fail "main does not point at the tag"; fi
if cmp -s "$check/templates/scan.yml" "$work/dist-1.2.3/scan.yml"; then pass "templates/scan.yml rendered"; else fail "templates/scan.yml differs"; fi
if grep -q 'ghcr.io/faridlamaul/shipguard:v1.2.3' "$check/templates/scan.yml"; then pass "image tag v1.2.3 in template"; else fail "image tag missing"; fi
if [ ! -e "$check/templates/old.yml" ]; then pass "stale template removed"; else fail "stale template kept"; fi
if [ -f "$check/other.txt" ]; then pass "unrelated file kept"; else fail "unrelated file removed"; fi
for f in README.md LICENSE; do
  if cmp -s "$check/$f" "$root/$f"; then pass "$f copied"; else fail "$f not copied"; fi
done
if cmp -s "$check/.gitlab-ci.yml" "$root/adapters/gitlab/publish/.gitlab-ci.yml"; then pass ".gitlab-ci.yml copied"; else fail ".gitlab-ci.yml not copied"; fi
if cmp -s "$check/test/.gitlab-ci.yml" "$root/adapters/gitlab/test/.gitlab-ci.yml"; then pass "test/.gitlab-ci.yml copied"; else fail "test/.gitlab-ci.yml not copied"; fi
if cmp -s "$check/test/ci.gitlab-ci.yml" "$root/adapters/gitlab/test/ci.gitlab-ci.yml"; then pass "test/ci.gitlab-ci.yml copied"; else fail "test/ci.gitlab-ci.yml not copied"; fi
if cmp -s "$check/test/fixtures/go-pass/go.mod" "$root/testdata/ci/go/pass/go.mod"; then pass "go-pass fixture copied"; else fail "go-pass fixture not copied"; fi
if cmp -s "$check/templates/ci.yml" "$work/dist-1.2.3/ci.yml"; then pass "templates/ci.yml rendered"; else fail "templates/ci.yml differs"; fi
hash=$(awk '$1 ~ /\/scan\.yml$/ {print $2}' "$work/integrity-1.2.3.txt")
if grep -qx "templates/scan.yml $hash" "$check/INTEGRITY.md"; then pass "INTEGRITY.md has the hash line"; else fail "INTEGRITY.md: $(cat "$check/INTEGRITY.md" 2> /dev/null)"; fi
if grep -qF 'integrity: sha256-' "$check/INTEGRITY.md"; then pass "INTEGRITY.md has the usage note"; else fail "INTEGRITY.md usage note"; fi
# The usage example pins scan.yml (no required inputs), not the first file
# alphabetically (ci.yml needs inputs and would not work as a copy-paste).
if grep -A1 -E '^  - remote: https://.*/-/raw/1\.2\.3/templates/scan\.yml$' "$check/INTEGRITY.md" | grep -qx "    integrity: $hash"; then
  pass "INTEGRITY.md example pins scan.yml with its hash"
else
  fail "INTEGRITY.md example: $(sed -n '/^include:/,/integrity:/p' "$check/INTEGRITY.md")"
fi
no_token "$work/out1"
no_token "$check/.git/config" "$work/main.git/config"

# The Bitbucket example is rendered next to the GitLab set, never into it.
bb=$work/bitbucket/build-test-pipelines.yml
if [ ! -e "$work/bitbucket" ]; then pass "no bitbucket output without the third argument"; else fail "bitbucket rendered without the third argument"; fi
"$root/scripts/render-gitlab.sh" 1.2.3 "$work/dist-bb" "$work/bitbucket" > /dev/null
if grep -qx ' *SHIPGUARD_RELEASE="v1.2.3"' "$bb"; then pass "bitbucket example pins SHIPGUARD_RELEASE"; else fail "bitbucket SHIPGUARD_RELEASE"; fi
if [ -f "$bb" ] && grep -q "$SHIPGUARD_BIN_SHA256_AMD64" "$bb" && grep -q "$SHIPGUARD_BIN_SHA256_ARM64" "$bb"; then pass "bitbucket example has both hashes"; else fail "bitbucket example hashes"; fi
if grep -q '__SHIPGUARD_' "$bb"; then fail "bitbucket example placeholder left"; else pass "bitbucket example has no placeholder"; fi
if grep -q 'v1.2.3' "$bb"; then pass "bitbucket example has the version"; else fail "bitbucket example version"; fi
if [ ! -e "$work/dist-1.2.3/build-test-pipelines.yml" ] && [ ! -e "$check/templates/build-test-pipelines.yml" ]; then pass "bitbucket example not in the GitLab set"; else fail "bitbucket example leaked into the GitLab set"; fi

# 2. Publishing the same version again is refused: a published tag never moves.
if publish main 1.2.3 "$work/out2"; then fail "re-publish 1.2.3 succeeded"; else
  rc=$?
  if [ "$rc" = 1 ]; then pass "re-publish exits 1"; else fail "re-publish exited $rc"; fi
  if grep -q 'already exists' "$work/out2"; then pass "re-publish names the existing tag"; else fail "re-publish output: $(cat "$work/out2")"; fi
fi
no_token "$work/out2"

# 3. The byte-compare after the push catches a remote that serves other bytes.
# A post-receive hook (test only) rewrites the tag to a commit with a tampered
# template, as a compromised or misbehaving remote would.
new_remote tamper
cat > "$work/tamper.git/hooks/post-receive" << 'EOF'
#!/bin/sh
set -eu
grep -q ' refs/tags/1.3.0$' || exit 0
export GIT_AUTHOR_NAME=x GIT_AUTHOR_EMAIL=x@example.com GIT_COMMITTER_NAME=x GIT_COMMITTER_EMAIL=x@example.com
base=$(git rev-parse 'refs/tags/1.3.0^{commit}')
blob=$(echo tampered | git hash-object -w --stdin)
export GIT_INDEX_FILE="$PWD/tamper-index"
git read-tree "$base"
git update-index --cacheinfo "100644,$blob,templates/scan.yml"
commit=$(git commit-tree "$(git write-tree)" -p "$base" -m tampered)
git update-ref refs/tags/1.3.0 "$commit"
rm -f "$GIT_INDEX_FILE"
EOF
chmod +x "$work/tamper.git/hooks/post-receive"
if publish tamper 1.3.0 "$work/out3"; then fail "tampered publish succeeded"; else
  rc=$?
  if [ "$rc" = 1 ]; then pass "tampered publish exits 1"; else fail "tampered publish exited $rc: $(cat "$work/out3")"; fi
  if grep -q 'templates/scan.yml' "$work/out3"; then pass "verify names the tampered file"; else fail "verify output: $(cat "$work/out3")"; fi
fi
no_token "$work/out3"

# 4. Usage and config errors exit 2.
usage() { # usage NAME ENV...: expects exit 2
  name=$1
  shift
  set +e
  env "$@" "$root/scripts/publish-gitlab.sh" > "$work/usage.out" 2>&1
  rc=$?
  set -e
  if [ "$rc" = 2 ]; then pass "$name exits 2"; else fail "$name exited $rc: $(cat "$work/usage.out")"; fi
  no_token "$work/usage.out"
}
"$root/scripts/render-gitlab.sh" 1.2.3 "$work/dist-u" > "$work/integrity-u.txt"
ok="RENDERED_DIR=$work/dist-u INTEGRITY_FILE=$work/integrity-u.txt"
# shellcheck disable=SC2086 # $ok is a list of NAME=value words
{
  usage "missing token" VERSION=1.2.3 $ok
  usage "bad version" VERSION=v1.2.3 GITLAB_PUBLISH_TOKEN="$token" $ok
  usage "prerelease version" VERSION=1.3.0-rc.1 GITLAB_PUBLISH_TOKEN="$token" $ok
  usage "bad repo" VERSION=1.2.3 GITLAB_PUBLISH_TOKEN="$token" PUBLISH_REPO='gitlab.com' $ok
  usage "repo with scheme" VERSION=1.2.3 GITLAB_PUBLISH_TOKEN="$token" PUBLISH_REPO='https://gitlab.com/a/b' $ok
  usage "file:// without test flag" VERSION=1.2.3 GITLAB_PUBLISH_TOKEN="$token" PUBLISH_BASE_URL=file:/// PUBLISH_REPO="${work#/}/main.git" $ok
  usage "other base URL" VERSION=1.2.3 GITLAB_PUBLISH_TOKEN="$token" PUBLISH_BASE_URL=http:// $ok
  usage "missing integrity file" VERSION=1.2.3 GITLAB_PUBLISH_TOKEN="$token" RENDERED_DIR="$work/dist-u"
}
printf 'templates/scan.yml sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' > "$work/integrity-bad.txt"
usage "integrity mismatch" VERSION=1.2.3 GITLAB_PUBLISH_TOKEN="$token" RENDERED_DIR="$work/dist-u" INTEGRITY_FILE="$work/integrity-bad.txt"

# 5. render-gitlab.sh with binary hashes: a temporary root (script + templates)
# holds a ci.yml template with the placeholders; scan.yml has none.
rr=$work/render-root
mkdir -p "$rr/scripts" "$rr/adapters/gitlab"
cp "$root/scripts/render-gitlab.sh" "$rr/scripts/"
cp "$root/adapters/gitlab/scan.yml" "$rr/adapters/gitlab/"
cat > "$rr/adapters/gitlab/ci.yml" << 'EOF'
image: ghcr.io/faridlamaul/shipguard:__SHIPGUARD_VERSION__
amd64: __SHIPGUARD_BIN_SHA256_AMD64__
arm64: __SHIPGUARD_BIN_SHA256_ARM64__
EOF
h1=$(printf 'a%.0s' $(seq 64))
h2=$(printf '1%.0s' $(seq 64))
render_rc() { # render_rc NAME EXPECTED_RC ENV...
  name=$1 want=$2
  shift 2
  set +e
  env "$@" "$rr/scripts/render-gitlab.sh" 1.2.3 "$work/dist-r" > "$work/render.out" 2>&1
  rc=$?
  set -e
  if [ "$rc" = "$want" ]; then pass "$name exits $want"; else fail "$name exited $rc: $(cat "$work/render.out")"; fi
}
render_rc "render without hashes" 2 -u SHIPGUARD_BIN_SHA256_AMD64 -u SHIPGUARD_BIN_SHA256_ARM64
render_rc "render with one hash" 2 -u SHIPGUARD_BIN_SHA256_ARM64 SHIPGUARD_BIN_SHA256_AMD64="$h1"
render_rc "render with short hash" 2 SHIPGUARD_BIN_SHA256_AMD64="$h1" SHIPGUARD_BIN_SHA256_ARM64=abc
render_rc "render with uppercase hash" 2 SHIPGUARD_BIN_SHA256_AMD64="$h1" SHIPGUARD_BIN_SHA256_ARM64="$(printf 'A%.0s' $(seq 64))"
nl='
'
render_rc "render with a multi-line hash" 2 SHIPGUARD_BIN_SHA256_AMD64="$h1" SHIPGUARD_BIN_SHA256_ARM64="$h2${nl}$h2"
render_rc "render with a trailing-newline hash" 2 SHIPGUARD_BIN_SHA256_AMD64="$h1" SHIPGUARD_BIN_SHA256_ARM64="$h2$nl"
render_rc "render with a sed payload" 2 SHIPGUARD_BIN_SHA256_AMD64="$h1" SHIPGUARD_BIN_SHA256_ARM64="$h2/;e id;s/x/$nl$h2"
render_rc "render with both hashes" 0 SHIPGUARD_BIN_SHA256_AMD64="$h1" SHIPGUARD_BIN_SHA256_ARM64="$h2"
if grep -qx "amd64: $h1" "$work/dist-r/ci.yml" && grep -qx "arm64: $h2" "$work/dist-r/ci.yml"; then pass "ci.yml has both hashes"; else fail "ci.yml: $(cat "$work/dist-r/ci.yml")"; fi
if grep -q '__SHIPGUARD_' "$work/dist-r/ci.yml" "$work/dist-r/scan.yml"; then fail "placeholder left"; else pass "no placeholder left"; fi
rm "$rr/adapters/gitlab/ci.yml"
render_rc "render without binary placeholders needs no hashes" 0 -u SHIPGUARD_BIN_SHA256_AMD64 -u SHIPGUARD_BIN_SHA256_ARM64
printf 'x: __SHIPGUARD_VERSION__ __SHIPGUARD_BIN_SHA256_MIPS__\n' > "$rr/adapters/gitlab/ci.yml"
render_rc "render with an unknown placeholder" 1 SHIPGUARD_BIN_SHA256_AMD64="$h1" SHIPGUARD_BIN_SHA256_ARM64="$h2"

# ---- shared ci job script (GitLab template and Bitbucket snippet) ----
gl_ci=$root/adapters/gitlab/ci.yml
bb_ci=$root/examples/bitbucket/build-test-pipelines.yml
# The image tag must not become SHIPGUARD_TOOLCHAIN: it would replace the
# detected version and hide a mismatch between the repo and the image.
for f in "$gl_ci" "$bb_ci"; do
  if grep -q 'SHIPGUARD_TOOLCHAIN' "$f"; then fail "$(basename "$f") sets SHIPGUARD_TOOLCHAIN"; else pass "$(basename "$f") leaves SHIPGUARD_TOOLCHAIN unset"; fi
  if grep -q 'SHIPGUARD_LANGUAGE' "$f"; then pass "$(basename "$f") sets SHIPGUARD_LANGUAGE"; else fail "$(basename "$f") lacks SHIPGUARD_LANGUAGE"; fi
  # Under set -eu a bare `exit "$rc"` ends Bitbucket's shared shell even on
  # success, skipping the user's script lines after the anchor.
  if grep -qE '^[[:space:]]*exit "\$rc"[[:space:]]*$' "$f"; then fail "$(basename "$f") ends with a bare exit"; else pass "$(basename "$f") has no bare exit"; fi
  if grep -qF '[ "$rc" -eq 0 ] || exit "$rc"' "$f"; then pass "$(basename "$f") exits only on failure"; else fail "$(basename "$f") lacks the conditional exit"; fi
done
# tail_of FILE: the run-and-report lines, without indentation and comments.
tail_of() { awk '/^[[:space:]]*rc=0$/ { on = 1 } on { sub(/^[[:space:]]+/, ""); if ($0 !~ /^#/) print } /exit "\$rc"/ { on = 0 }' "$1"; }
if [ -n "$(tail_of "$gl_ci")" ] && [ "$(tail_of "$gl_ci")" = "$(tail_of "$bb_ci")" ]; then pass "GitLab and Bitbucket job tails match"
else fail "job tails differ: $(tail_of "$gl_ci") // $(tail_of "$bb_ci")"; fi

if [ "$fails" -ne 0 ]; then
  echo "publish-gitlab-test: $fails failure(s)" >&2
  exit 1
fi
echo "publish-gitlab-test: all checks passed"
