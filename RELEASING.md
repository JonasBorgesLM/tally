# Releasing

One maintainer cuts releases. These are the steps that are easy to get backwards under pressure. The branch
model is in [`CONTRIBUTING.md`](CONTRIBUTING.md#git-flow).

**No release has been cut, and the release workflow does not exist yet (#57).** The steps below are vane's,
which have been run; what is specific to tally's verifier is marked as not yet exercised.

## Before the first tag

The first public tag cannot be taken back, and moat learned that the hard way.

- [ ] `go.mod` read by a human: module path, `go` line.
- [ ] From a clean directory with no workspace, `go install` and `go get` resolve the tag.
- [ ] The CHANGELOG comes from a real API diff, not from memory.
- [ ] The clean-session audit (#56) is done, and findings are fixed or accepted with a reason.
- [ ] A `retract` plan is written down: what would be retracted, and with which release.

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

## What the verifier's release must carry (not yet exercised, #57)

`tally verify` is the auditor's root of trust (ADR-0014, T-18), so beyond the steps above: a build with
`-trimpath` and an embedded version, two builds of one tag compared byte for byte, signed checksums, an SBOM, and
build provenance. Each refusal path in the workflow gets watched failing before anyone trusts it.

## A bad release

A tag is never moved. Fix forward with a new version and `retract` the bad one in `go.mod`, so `go get` skips it.
