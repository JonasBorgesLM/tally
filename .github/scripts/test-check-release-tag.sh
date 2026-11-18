#!/usr/bin/env bash
#
# Every refusal of check-release-tag.sh, seen failing (#57), and one tag seen
# passing: each case builds the tag it needs in a throwaway repository, with
# a throwaway signing key, so no tag is ever pushed anywhere.
#
#   ./.github/scripts/test-check-release-tag.sh
#
# Needs git and ssh-keygen.

set -uo pipefail
check="$(cd "$(dirname "$0")" && pwd)/check-release-tag.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ssh-keygen -q -t ed25519 -N '' -C allowed -f "$work/allowed"
ssh-keygen -q -t ed25519 -N '' -C stranger -f "$work/stranger"

repo="$work/repo"
git init -q -b main "$repo"
cd "$repo" || exit 1
git config user.email release@example.test
git config user.name release
git config gpg.format ssh
git config commit.gpgsign false
git config tag.gpgsign false
mkdir -p .github
printf 'release@example.test namespaces="git" %s\n' "$(cat "$work/allowed.pub")" >.github/allowed_signers
printf '# Changelog\n\n## [1.0.0] - 2026-11-18\n\n## [1.1.0] - 2026-11-18\n' >CHANGELOG.md
git add . && git commit -q -m "release state"

signed() { git -c user.signingkey="$work/allowed" tag -s -m "$1" "$1" "${2:-HEAD}"; }

failed=0
ran=0
expect() { # expect <case> <want status> <message substring> <tag>
  local out status
  out=$("$check" "$4" main 2>&1)
  status=$?
  ran=$((ran + 1))
  if [ "$status" -ne "$2" ] || ! printf '%s' "$out" | grep -qF "$3"; then
    echo "FAIL  $1: status $status, output: $out"
    failed=1
  else
    echo "ok    $1"
  fi
  git tag -d "$4" >/dev/null 2>&1 || true
}

signed v1.0.0
expect "a signed tag on main, the newest, in the CHANGELOG" 0 "ok    v1.0.0" v1.0.0

git tag -a -m release-1 release-1
expect "not SemVer" 1 "is not vX.Y.Z" release-1

git switch -q -c side
git commit -q --allow-empty -m "never merged"
signed v1.0.0
git switch -q main
expect "not on main" 1 "does not point to a commit on main" v1.0.0

signed v1.0.0
signed v1.1.0
expect "not the newest" 1 "expected v1.0.0 to be the newest tag" v1.0.0
git tag -d v1.1.0 >/dev/null

signed v2.0.0
expect "no CHANGELOG section" 1 "has no '## [2.0.0]' section" v2.0.0

git tag v1.0.0
expect "lightweight" 1 "is a lightweight tag" v1.0.0

git tag -a -m v1.0.0 v1.0.0
expect "annotated, unsigned" 1 "is not signed by a key" v1.0.0

git -c user.signingkey="$work/stranger" tag -s -m v1.0.0 v1.0.0
expect "signed by a key not allowed" 1 "is not signed by a key" v1.0.0

signed v1.1.0-rc.1
expect "a release candidate" 0 "prerelease=true" v1.1.0-rc.1

if [ "$ran" -ne 9 ]; then
  echo "FAIL  ran $ran cases, want 9"
  failed=1
fi
exit "$failed"
