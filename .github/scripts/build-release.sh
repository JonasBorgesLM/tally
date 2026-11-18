#!/usr/bin/env bash
#
# Builds the tally CLI for every release platform into OUT, as the release
# workflow publishes it (ADR-0014, #57):
#
#   ./.github/scripts/build-release.sh OUT VERSION
#
# Each build is meant to be reproducible: the same commit and the same Go
# toolchain give the same bytes, whoever builds it and wherever the checkout
# is. That is what lets an auditor rebuild a release and compare, rather than
# trust the pipeline. What makes it so:
#
# - CGO_ENABLED=0: no C toolchain, and nothing of the host's, in the binary.
# - -trimpath: no path of the build machine.
# - -buildid=: no build id, which otherwise hashes inputs that can differ.
# - -s -w: no symbol table or DWARF, which carry paths and are not needed.
# - the module and VCS stamp Go embeds name the commit, which is the same.
#
# The toolchain is part of the input: a different Go version builds different
# bytes. The release notes name the one used.

set -euo pipefail
cd "$(dirname "$0")/../.."

out=${1:?usage: build-release.sh OUT VERSION}
version=${2:?usage: build-release.sh OUT VERSION}
case "$version" in
  *[!A-Za-z0-9.+_-]*) echo "build-release: '$version' is not a version" >&2; exit 2 ;;
esac
mkdir -p "$out"

for platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  goos=${platform%/*}
  goarch=${platform#*/}
  bin="$out/tally_${version}_${goos}_${goarch}"
  CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch \
    go build -trimpath -ldflags "-s -w -buildid= -X main.version=${version}" -o "$bin" ./cmd/tally
  echo "built $(basename "$bin")"
done
