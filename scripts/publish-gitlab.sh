#!/bin/sh
# Publishes the rendered GitLab templates to the gitlab.com project that serves
# the CI/CD Catalog component and the `include: remote` URL.
#
# Environment:
#   VERSION               X.Y.Z, no leading v (required)
#   GITLAB_PUBLISH_TOKEN  project access token with write_repository (required)
#   INTEGRITY_FILE        output of scripts/render-gitlab.sh: "<file> sha256-<b64>" lines (required)
#   RENDERED_DIR          rendered templates (default dist/gitlab)
#   PUBLISH_REPO          host/path without scheme (default gitlab.com/faridlamaul/shipguard)
#   PUBLISH_BASE_URL      https:// (default); file:/// only with SHIPGUARD_PUBLISH_TEST=1,
#                         which scripts/publish-gitlab-test.sh uses for local bare repos
#
# It replaces templates/ on main, copies README.md, LICENSE and the publish
# pipeline, writes INTEGRITY.md, commits "release X.Y.Z", tags X.Y.Z, pushes
# both, then fetches the tag fresh and compares templates/ byte for byte with
# RENDERED_DIR. A tag that already exists on the remote is never moved.
#
# Exit codes: 0 published and verified, 1 publish or verify failure,
# 2 usage or config error.
set -eu

die() { echo "publish-gitlab: $2" >&2; exit "$1"; }

root=$(cd "$(dirname "$0")/.." && pwd)
version=${VERSION:-}
repo=${PUBLISH_REPO:-gitlab.com/faridlamaul/shipguard}
base=${PUBLISH_BASE_URL:-https://}
rendered=${RENDERED_DIR:-dist/gitlab}
integrity=${INTEGRITY_FILE:-}

# Same rule as render-gitlab.sh.
case $version in
  *[!0-9.]*|''|.*|*.|*..*) bad=1 ;;
  *) bad=0 ;;
esac
if [ "$bad" = 0 ] && ! printf '%s' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  bad=1
fi
[ "$bad" = 0 ] || die 2 "VERSION must be X.Y.Z without a leading v, got '$version'"

[ -n "${GITLAB_PUBLISH_TOKEN:-}" ] || die 2 "GITLAB_PUBLISH_TOKEN is not set"

if ! printf '%s' "$repo" | grep -Eq '^[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+$'; then
  die 2 "PUBLISH_REPO must be host/path without a scheme, got '$repo'"
fi
case $repo in
  *..*) die 2 "PUBLISH_REPO must not contain '..', got '$repo'" ;;
esac

case $base in
  https://) ;;
  file:///)
    [ "${SHIPGUARD_PUBLISH_TEST:-}" = 1 ] || die 2 "PUBLISH_BASE_URL file:/// is only allowed with SHIPGUARD_PUBLISH_TEST=1"
    ;;
  *) die 2 "PUBLISH_BASE_URL must be https://, got '$base'" ;;
esac
url=$base$repo

[ -d "$rendered" ] || die 2 "RENDERED_DIR '$rendered' is not a directory"
rendered=$(cd "$rendered" && pwd)
[ -n "$integrity" ] || die 2 "INTEGRITY_FILE is not set"
[ -f "$integrity" ] || die 2 "INTEGRITY_FILE '$integrity' does not exist"

hash_of() { # hash_of FILE: prints sha256-<base64>, the form `integrity:` takes
  h=$(openssl dgst -sha256 -binary "$1" | openssl base64 -A)
  [ "${#h}" -eq 44 ] || die 1 "hashing $1 failed"
  printf 'sha256-%s' "$h"
}

# The rendered files and their hashes. Each must match the integrity line that
# render-gitlab.sh printed for it (matched by file name), with no extra lines.
files=
count=0
for f in "$rendered"/*; do
  [ -e "$f" ] || continue
  name=$(basename "$f")
  [ -f "$f" ] || die 2 "RENDERED_DIR may only hold files, found '$name'"
  printf '%s' "$name" | grep -Eq '^[A-Za-z0-9._-]+$' || die 2 "unexpected file name '$name' in RENDERED_DIR"
  want=$(awk -v n="$name" 'NF { p = $1; sub(/.*\//, "", p); if (p == n) print $2 }' "$integrity")
  [ -n "$want" ] || die 2 "INTEGRITY_FILE has no line for $name"
  [ "$want" = "$(hash_of "$f")" ] || die 2 "INTEGRITY_FILE hash for $name does not match the rendered file"
  files="$files $name"
  count=$((count + 1))
done
[ "$count" -gt 0 ] || die 2 "RENDERED_DIR '$rendered' is empty"
lines=$(awk 'NF' "$integrity" | wc -l | tr -d ' ')
[ "$lines" -eq "$count" ] || die 2 "INTEGRITY_FILE has $lines lines for $count rendered files"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

# Credentials. The token stays in the environment: GIT_ASKPASS points at a
# helper that prints it when git asks for the password, so it never appears in
# argv (unlike a token in the URL or `-c http.extraHeader=...`), in the clone's
# .git/config, or in git's output. credential.helper is reset so no helper (for
# example a keychain) stores it, and git ignores the runner's global and system
# config, which also keeps commit signing off.
cat > "$tmp/askpass" << 'EOF'
#!/bin/sh
case $1 in
  Username*) echo oauth2 ;;
  *) printf '%s\n' "$GITLAB_PUBLISH_TOKEN" ;;
esac
EOF
chmod 700 "$tmp/askpass"
export GITLAB_PUBLISH_TOKEN GIT_ASKPASS="$tmp/askpass" GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=shipguard-release GIT_AUTHOR_EMAIL=noreply@github.com
export GIT_COMMITTER_NAME=shipguard-release GIT_COMMITTER_EMAIL=noreply@github.com
g() { git -c credential.helper= -c commit.gpgSign=false -c tag.gpgSign=false "$@"; }

echo "publish-gitlab: publishing $version to $url"
existing=$(g ls-remote --tags "$url" "refs/tags/$version") || die 1 "cannot list tags on $url"
[ -z "$existing" ] || die 1 "tag $version already exists on $url; a published tag is never moved"

work=$tmp/repo
g clone --quiet --depth 1 --no-single-branch "$url" "$work" || die 1 "cloning $url failed"
if g -C "$work" rev-parse --verify --quiet refs/remotes/origin/main > /dev/null; then
  g -C "$work" checkout --quiet -B main origin/main
else
  g -C "$work" checkout --quiet --orphan main
fi

g -C "$work" rm -r --quiet --ignore-unmatch -- templates > /dev/null
rm -rf "$work/templates"
mkdir -p "$work/templates" "$work/test"
for name in $files; do
  cp "$rendered/$name" "$work/templates/$name"
done
cp "$root/README.md" "$root/LICENSE" "$work/"
cp "$root/adapters/gitlab/publish/.gitlab-ci.yml" "$work/.gitlab-ci.yml"
# The publish pipeline includes the smoke test from test/.gitlab-ci.yml.
cp "$root/adapters/gitlab/test/.gitlab-ci.yml" "$work/test/.gitlab-ci.yml"
# The component smoke test runs on a copy of the Go pass fixture.
cp "$root/adapters/gitlab/test/ci.gitlab-ci.yml" "$work/test/ci.gitlab-ci.yml"
rm -rf "$work/test/fixtures"
mkdir -p "$work/test/fixtures/go-pass"
cp "$root"/testdata/ci/go/pass/* "$work/test/fixtures/go-pass/"

first=${files# }
first=${first%% *}
# shellcheck disable=SC2016 # the backticks are literal Markdown
{
  printf '# shipguard %s template hashes\n\n' "$version"
  printf 'Pin a template included by URL with its hash:\n\n'
  printf '```yaml\ninclude:\n  - remote: https://%s/-/raw/%s/templates/%s\n    integrity: %s\n```\n\n' \
    "$repo" "$version" "$first" "$(hash_of "$rendered/$first")"
  printf 'SHA-256 of each file in `templates/` at tag `%s`:\n\n```text\n' "$version"
  for name in $files; do
    printf 'templates/%s %s\n' "$name" "$(hash_of "$rendered/$name")"
  done
  printf '```\n'
} > "$work/INTEGRITY.md"

g -C "$work" add -A -- templates test/.gitlab-ci.yml test/ci.gitlab-ci.yml test/fixtures README.md LICENSE .gitlab-ci.yml INTEGRITY.md
g -C "$work" commit --quiet --allow-empty -m "release $version"
g -C "$work" tag -a -m "release $version" "$version"
# --atomic: the branch and the tag land together or not at all. Without
# --force, git also refuses a tag created on the remote since the check above.
g -C "$work" push --quiet --atomic origin main "refs/tags/$version" || die 1 "pushing main and tag $version to $url failed"

# Verify what the remote now serves: fetch the tag into an empty repository and
# compare every blob under templates/ with the rendered file.
check=$tmp/verify.git
g init --quiet --bare "$check"
g -C "$check" fetch --quiet --depth 1 "$url" "refs/tags/$version:refs/tags/$version" || die 1 "fetching tag $version back from $url failed"
rev="refs/tags/$version^{commit}"
got=$(g -C "$check" ls-tree -r --name-only "$rev" -- templates/ | LC_ALL=C sort)
want=$(for name in $files; do echo "templates/$name"; done | LC_ALL=C sort)
if [ "$got" != "$want" ]; then
  echo "publish-gitlab: verify: templates/ at tag $version holds:" >&2
  printf '%s\n' "$got" >&2
  die 1 "verify: expected exactly the rendered files: $(echo "$want" | tr '\n' ' ')"
fi
bad=0
for name in $files; do
  g -C "$check" cat-file blob "$rev:templates/$name" > "$tmp/blob"
  if ! cmp -s "$tmp/blob" "$rendered/$name"; then
    echo "publish-gitlab: verify: templates/$name at tag $version differs from $rendered/$name" >&2
    bad=1
  fi
done
[ "$bad" = 0 ] || die 1 "verify failed: tag $version is published but does not match the rendered templates"

echo "publish-gitlab: published and verified $version on $url"
