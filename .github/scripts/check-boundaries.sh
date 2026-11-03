#!/usr/bin/env bash
#
# Dependency and package-boundary guards.
#
# A file rather than inline YAML so it runs locally before a push:
#
#   ./.github/scripts/check-boundaries.sh
#
# Every check asks the Go resolver (`go list`), never greps go.mod: grepping a
# manifest matched a comment naming a dependency in another repository of this
# ecosystem and passed.
#
# Several packages named here do not exist yet (docs/architecture.md). A rule over
# an absent package is satisfied trivially, so check 0 asserts that the packages
# exist that should, and each new one has to be added to KNOWN below: a package
# that no rule knows about fails instead of passing unexamined.
#
# Run for each supported platform (RNF-09): the fsx backends will sit behind build
# tags, and `go list` only sees the imports of files that build on its GOOS.

set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

export CGO_ENABLED=0
MOD=$(go list -m) || { echo "go list -m failed; the module does not resolve"; exit 1; }

# Every package of this module, relative to the module, "." for the root.
KNOWN=". anchor cmd/tally filestore seal tallytest internal/fsx internal/note internal/wire"

FAILED=0
fail() { printf '\n\033[31mFAIL\033[0m  %s\n' "$1"; FAILED=1; }
pass() { printf '\033[32mok\033[0m    %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }

rel() { local p="${1#"$MOD"}"; p="${p#/}"; printf '%s' "${p:-.}"; }

# --- 1. The core is stdlib only, whatever any file claims (RNF-01, RI-01) -----
#
# Asks for the module graph, so a dependency nothing imports yet still fails.
mods=$(go list -m all) || { fail "go list -m all failed"; exit 1; }
if [ "$mods" = "$MOD" ]; then
  pass "the module graph is exactly $MOD (RNF-01)"
else
  fail "the module graph holds more than $MOD:"
  printf '%s\n' "$mods" | grep -vx "$MOD" | sed 's/^/        /'
  note "The core is stdlib only (RNF-01), and no ecosystem library may be imported"
  note "(RI-01). A differential test that needs a module goes in interop/."
fi

for goos in linux darwin; do
  export GOOS=$goos
  printf '\n[%s]\n' "$goos"

  # Each line: <package> <direct non-test imports>
  imports=$(go list -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}' ./...) || {
    fail "go list failed for $goos"; continue; }
  # Each line: <package> <direct imports, including test imports>
  all_imports=$(go list -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}{{range .TestImports}} {{.}}{{end}}{{range .XTestImports}} {{.}}{{end}}' ./...) || {
    fail "go list failed for $goos"; continue; }

  # --- 0. The rules below are looking at something ---------------------------
  #
  # An empty answer satisfies every negative rule, so the expected answer is
  # asserted first.
  if printf '%s\n' "$imports" | grep -q "^$MOD\( \|$\)"; then
    pass "go list sees the root package"
  else
    fail "go list does not see the root package, so nothing below means anything"
  fi
  unknown=""
  while read -r pkg _; do
    r=$(rel "$pkg")
    case " $KNOWN " in *" $r "*) ;; *) unknown="$unknown $r" ;; esac
  done <<< "$imports"
  if [ -n "$unknown" ]; then
    fail "packages no rule knows about:$unknown"
    note "Add each to KNOWN and decide its rules here, in the pull request creating it."
    note "docs/architecture.md says where it sits in the dependency direction."
  else
    pass "every package is one this script knows ($(printf '%s\n' "$imports" | wc -l | tr -d ' '))"
  fi

  # --- 2. Nothing outside the module is reachable, tests included -------------
  #
  # stdlib-vendored golang.org/x paths report as standard, so .Standard is the
  # resolver's own answer rather than a prefix guess.
  ext=$(go list -deps -test -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... | sed 's/ \[.*//; s/\.test$//' | grep -v "^$MOD\(/\|$\)" | sort -u)
  if [ -z "$ext" ]; then
    pass "no non-standard package reachable, tests included (RNF-01)"
  else
    fail "non-standard packages reachable: $(printf '%s' "$ext" | tr '\n' ' ')"
  fi

  # --- 3. No unsafe anywhere; no reflection on the encoding path (RS-11) ------
  bad=$(printf '%s\n' "$all_imports" | awk '{for (i=2;i<=NF;i++) if ($i=="unsafe") print $1}')
  if [ -z "$bad" ]; then
    pass "no package imports unsafe (RS-11)"
  else
    fail "imports unsafe: $bad"
    note "RS-11: the encoding, hash and durability paths have to be reviewable."
  fi
  bad=$(printf '%s\n' "$imports" | awk -v w="$MOD/internal/wire" -v n="$MOD/internal/note" \
    '$1==w || $1==n {for (i=2;i<=NF;i++) if ($i=="reflect") print $1}')
  if [ -z "$bad" ]; then
    pass "no reflect in internal/wire or internal/note (RS-11)"
  else
    fail "imports reflect on the encoding path: $bad"
  fi

  # --- 4. Dependency direction (docs/architecture.md) -------------------------
  #
  # A subpackage importing the root is fine. The reverse is an import cycle at
  # best, and at worst a core that quietly grew a dependency on an implementation.
  bad=$(printf '%s\n' "$imports" | awk -v m="$MOD" '$1==m {for (i=2;i<=NF;i++) if (index($i, m"/")==1 && index($i, m"/internal/")!=1) print $i}')
  if [ -z "$bad" ]; then
    pass "the root imports only internal/* of this module"
  else
    fail "the root imports a subpackage: $bad"
  fi
  bad=$(printf '%s\n' "$imports" | awk -v m="$MOD" 'index($1, m"/internal/")==1 {for (i=2;i<=NF;i++) if ($i==m || (index($i, m"/")==1 && index($i, m"/internal/")!=1)) print $1" -> "$i}')
  if [ -z "$bad" ]; then
    pass "internal/* imports nothing above it"
  else
    fail "internal/* imports upward: $bad"
  fi

  # --- 5. Test helpers do not reach production --------------------------------
  bad=$(printf '%s\n' "$imports" | awk -v t="$MOD/tallytest" '$1!=t {for (i=2;i<=NF;i++) if ($i==t) print $1}')
  if [ -z "$bad" ]; then
    pass "no production package imports tallytest"
  else
    fail "production code imports tallytest: $bad"
  fi
done
unset GOOS

echo
if [ "$FAILED" -ne 0 ]; then echo "Boundary checks failed."; exit 1; fi
echo "Boundary checks passed."
