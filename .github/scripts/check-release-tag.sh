#!/usr/bin/env bash
#
# The release workflow's refusals (ADR-0014, #57), before any release exists:
#
#   ./.github/scripts/check-release-tag.sh TAG [MAIN_REF]
#
# It refuses, with exit 1 and one ::error:: line, a tag that is:
#
#   1. not vX.Y.Z or vX.Y.Z-rc.N;
#   2. on a commit that is not on MAIN_REF (default origin/main): git flow
#      puts only released states on main;
#   3. not the newest tag, so an old tag re-pushed cannot publish under it;
#   4. without a "## [X.Y.Z]" section in the tagged commit's CHANGELOG.md;
#   5. not an annotated tag signed by a key in the tagged commit's
#      .github/allowed_signers.
#
# A script rather than inline YAML so that every refusal can be seen failing
# (.github/scripts/test-check-release-tag.sh), not trusted on reading. When
# GITHUB_OUTPUT is set, it writes prerelease=true|false there.

set -uo pipefail

tag=${1:?usage: check-release-tag.sh TAG [MAIN_REF]}
main_ref=${2:-origin/main}

refuse() {
  echo "::error::$*"
  exit 1
}

# 1. SemVer, and nothing else in the name.
# grep to /dev/null, never -q, after a pipe: under pipefail, -q exits at the
# first match and the writer dies of SIGPIPE, which fails the pipeline.
if ! printf '%s' "$tag" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$' >/dev/null; then
  refuse "'$tag' is not vX.Y.Z or vX.Y.Z-rc.N"
fi
commit=$(git rev-parse --verify --quiet "refs/tags/$tag^{commit}") || refuse "there is no tag $tag"

# 2. On main.
git rev-parse --verify --quiet "$main_ref" >/dev/null || refuse "$main_ref does not exist; fetch it first"
git merge-base --is-ancestor "$commit" "$main_ref" || refuse "$tag does not point to a commit on $main_ref"

# 3. The newest tag. -rc tags sort before their release.
newest=$(git -c versionsort.suffix=-rc. tag --list 'v*' --sort=-v:refname | head -1)
[ "$newest" = "$tag" ] || refuse "expected $tag to be the newest tag, found '${newest:-<none>}'"

# 4. A CHANGELOG section for the version, in the tagged commit.
version=${tag#v}
version=${version%%-rc.*}
git show "$commit:CHANGELOG.md" 2>/dev/null | grep -E "^## \[${version//./\\.}\]" >/dev/null ||
  refuse "CHANGELOG.md at $tag has no '## [$version]' section"

# 5. Annotated, and signed by an allowed key, from the tagged commit's list.
[ "$(git cat-file -t "refs/tags/$tag")" = "tag" ] || refuse "$tag is a lightweight tag; a release tag is annotated and signed"
signers=$(mktemp)
trap 'rm -f "$signers"' EXIT
git show "$commit:.github/allowed_signers" >"$signers" 2>/dev/null || refuse "$tag has no .github/allowed_signers"
grep -qvE '^(#|$)' "$signers" || refuse ".github/allowed_signers at $tag has no key; no release can be verified"
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$signers" verify-tag "$tag" >/dev/null 2>&1 ||
  refuse "$tag is not signed by a key in .github/allowed_signers"

case "$tag" in
  *-rc.*) prerelease=true ;;
  *) prerelease=false ;;
esac
[ -n "${GITHUB_OUTPUT:-}" ] && echo "prerelease=$prerelease" >>"$GITHUB_OUTPUT"
echo "ok    $tag: SemVer, on $main_ref, the newest, in the CHANGELOG, signed by an allowed key (prerelease=$prerelease)"
