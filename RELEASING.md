# Releasing

One maintainer cuts releases. These are the steps that are easy to get backwards under pressure. The branch
model is in [`CONTRIBUTING.md`](CONTRIBUTING.md#git-flow).

**v0.1.0 was the first release** cut through this file and the release workflow (`.github/workflows/release.yml`,
#57), after `v0.1.0-rc.1` as the workflow's first run (#58); v0.2.0 followed the same steps.

## Before the first tag

The first public tag cannot be taken back, and moat learned that the hard way.

- [ ] `go.mod` read by a human: module path, `go` line.
- [ ] From a clean directory with no workspace, `go install` and `go get` resolve the tag.
- [ ] The CHANGELOG comes from a real API diff, not from memory.
- [ ] The clean-session audit (#56) is done, and findings are fixed or accepted with a reason.
- [ ] A `retract` plan is written down: what would be retracted, and with which release. It is below.

### The retract plan

A bad release is never fixed by moving or deleting its tag: the proxy and every `go.sum` keep it. Instead:

1. **A release candidate that fails** (`v0.1.0-rc.N`) is not retracted. Nothing resolves to a prerelease unless
   someone asks for it by name, so the next `-rc.N+1` supersedes it, and the release notes of the failed one say
   why.
2. **A release that is bad** (`vX.Y.Z`: it does not build, it does not resolve, or `tally verify` says intact
   when it should not) is retracted in the next patch release. That release's `go.mod` gains
   `retract vX.Y.Z // <the reason, one line>`, its CHANGELOG says what was wrong, and its own tag goes through
   this file like any other.
3. **A security defect** gets the same retract and, before it, a GitHub security advisory (SECURITY.md).
   `tally verify` from the bad release is listed by version in the advisory, since auditors may still hold it.

`go list -m -versions github.com/JonasBorgesLM/tally` shows what remains selectable after a retract; check it
from a clean directory, with no workspace, once the fix is published.

## Cutting a release

**1. Release branch from the `develop` commit you verified.**

```bash
git switch develop && git pull --ff-only
git switch -c release/vX.Y.Z
```

Only release edits go here: rename `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD`, open a
fresh `[Unreleased]` above it, and fix what verification finds. Features wait for the next release.

**2. Verify on that commit, not from memory.** CI on the release pull request, plus the attack suite.

**3. Pull request into `main`, merged with a merge commit.**

```bash
gh pr create --base main --title "chore(release): vX.Y.Z" --body "Verified on <sha>: <CI run>."
gh pr merge --merge
```

**4. Tag the merge commit on `main`, signed and annotated.**

```bash
git switch main && git pull --ff-only
git tag -a vX.Y.Z -m "vX.Y.Z — <one line on what it carries>"
git tag -v vX.Y.Z          # must print "Good \"git\" signature"
git push origin vX.Y.Z
```

The failure mode is forgetting `-a`: `git tag vX.Y.Z` makes a lightweight, unsigned tag silently. The key that
signs must be in [`.github/allowed_signers`](.github/allowed_signers).

**5. Merge back.**

```bash
gh pr create --base develop --head main \
  --title "chore(release): merge vX.Y.Z back into develop" --body "After vX.Y.Z."
gh pr merge --merge
```

## What the workflow does with a tag (ADR-0014, #57)

`tally verify` is the auditor's root of trust (T-18), so pushing a tag runs `release.yml`, which publishes nothing
until every step below has passed:

1. **verify.** `.github/scripts/check-release-tag.sh` refuses a tag that is:
   - not `vX.Y.Z` or `vX.Y.Z-rc.N`;
   - on a commit that is not on `main`;
   - not the newest tag;
   - without a CHANGELOG section;
   - lightweight, unsigned, or signed by a key that is not in `.github/allowed_signers`.

   CI's "release checks" job sees each of those refusals fail on every pull request, in a throwaway repository
   (`test-check-release-tag.sh`). Then verify builds and tests the module as a consumer resolves it, runs interop
   and govulncheck, and generates the API diff.
2. **build, twice.** `.github/scripts/build-release.sh` builds `tally` for linux and darwin, amd64 and arm64:
   `CGO_ENABLED=0`, `-trimpath`, `-buildid=`, `-s -w`, and `-X main.version=<tag>`, so `tally version` names the
   release. It runs on two runners, from two checkouts, with no cache.
3. **reproducible.** The two builds are compared byte for byte, and any difference stops the release. CI's
   "release checks" job does the same on every pull request, so a change that breaks reproducibility fails
   there first.
4. **release.**
   - The files: the binaries, an uncompressed source tarball, a CycloneDX SBOM of the binary (empty of
     components, since the module is stdlib only), and `SHA256SUMS`.
   - Build provenance for every file, signed through Sigstore with the workflow's identity.
   - Notes from the CHANGELOG section and the API diff, with the commands below.

### How an auditor checks a release

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify tally_vX.Y.Z_linux_amd64 --repo JonasBorgesLM/tally
./tally_vX.Y.Z_linux_amd64 version          # tally vX.Y.Z
```

Or rebuild it and compare. From a checkout of the tag, with the Go version the notes name:

```bash
./.github/scripts/build-release.sh ./rebuilt vX.Y.Z && sha256sum ./rebuilt/*
```

`gh attestation verify` was tried on `v0.1.0-rc.1` and `v0.1.0` (#58): every file verified, and a copy with one byte
changed was refused. What provenance
does not cover: a compromised CI still attests what it built, since provenance names the pipeline, not its
honesty (ADR-0014). The rebuild is the check that does not depend on it, and SPEC is enough to write a verifier
of one's own.

## A bad release

A tag is never moved. Fix forward with a new version and `retract` the bad one in `go.mod`, so `go get` skips it.
