package attack_test

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var writeREADME = flag.Bool("write-readme", false, "regenerate the README's attack table (review the diff before committing)")

// result is what a threat's test asserts.
type result string

const (
	// detected: the attack is reported, as the kind of violation named.
	resDetected result = "Detected"
	// mitigated: the attack is made harder or harmless, not detected.
	resMitigated result = "Mitigated"
	// partial: the test asserts the threat's limit, what is NOT caught, so the
	// README cannot claim more than the code does.
	resPartial result = "Partial, limit asserted"
)

// entry maps a threat to the test that covers it. pkg is the test's package
// directory, relative to the module root.
type entry struct {
	threat string
	result result
	pkg    string
	test   string
	shows  string
}

// registry is the attack suite: one test per threat of docs/THREAT-MODEL.md.
// Tests that already existed beside the code they cover are named in place,
// not duplicated; each was seen failing with its protection removed, as its
// own comment records.
var registry = []entry{
	{"T-01", resPartial, "attack", "TestT01AlterAnEntry",
		"Inside a checkpoint: `PrevHashMismatch`. Past the last one, an entry rewritten with nothing after it verifies, counted as unattested."},
	{"T-02", resDetected, "attack", "TestT02RemoveFromTheMiddle", "`SeqGap`."},
	{"T-03", resDetected, "attack", "TestT03InsertAForgedEntry",
		"`SeqRegression`, even for an entry chained to its predecessor."},
	{"T-04", resDetected, "attack", "TestT04Reorder", "`SeqGap`."},
	{"T-05", resPartial, ".", "TestT05TruncationIsSeenOnlyAgainstTheAnchor",
		"`TruncatedBelowCheckpoint` against the anchor; on the host's word alone, nothing."},
	{"T-06", resDetected, "attack", "TestT06RewriteWithoutTheKey",
		"`ForkDetected` against the anchor; the host's own checkpoints are `UnknownKey`."},
	{"T-07", resPartial, ".", "TestT07RewriteWithTheKeyIsAForkAgainstTheAnchor",
		"`ForkDetected`, only against a checkpoint anchored before the rewrite."},
	{"T-08", resPartial, ".", "TestT08RollbackIsSeenOnlyAgainstTheAnchor",
		"`TruncatedBelowCheckpoint` against the anchor; on the host's word alone, nothing."},
	{"T-09", resPartial, "attack", "TestT09SplitView",
		"Two histories each verify against their own anchor; one shared anchor makes the second a fork."},
	{"T-10", resDetected, "attack", "TestT10SpliceAcrossLogs", "`MalformedRecord`: another log's `log_id`."},
	{"T-11", resDetected, "attack", "TestT11DuplicateAnEntry", "`SeqRegression`."},
	{"T-12", resMitigated, "filestore", "TestTruncatedAtEveryByte",
		"Cut at every byte, the log reopens to the frames before the cut, or refuses below a checkpoint."},
	{"T-13", resDetected, ".", "TestEveryKindIsProduced", "`NonCanonicalEncoding`, among every violation kind."},
	{"T-14", resPartial, "attack", "TestT14BackdatingByTheCaller",
		"An `occurred_at` fifty years back verifies: it is the caller's claim."},
	{"T-15", resPartial, ".", "TestT15HeartbeatGaps",
		"`HeartbeatGap` when the anchored heartbeats stop; heartbeats over a log missing events pass."},
	{"T-16", resMitigated, "filestore", "TestTheObserverHearsOfLowSpaceBeforeWritesFail",
		"The Observer hears of low space before writes fail; a full disk still stops the log."},
	{"T-17", resMitigated, "cmd/tally", "TestAFieldCannotForgeALine",
		"A line break or an ESC in a field cannot forge a line of output or reach the terminal."},
	{"T-18", resPartial, ".", "TestRecordVectors",
		"The published vectors let an independent verifier check tally; no test can vouch for the binary it runs in."},
	{"T-19", resMitigated, "attack", "TestT19PersonalPayloadsOnDisk",
		"Sealed payloads are ciphertext on disk, the identifier is nowhere, and the vault opens under no other KEK."},
	{"T-20", resPartial, "attack", "TestT20LinkAfterAShred",
		"After a shred the payloads are gone, and the ref still links the subject's entries."},
	{"T-21", resPartial, "attack", "TestT21RewriteTheAnchorFromTheHost",
		"A host that rewrites a host-writable anchor passes verification against it."},
	{"T-22", resPartial, "attack", "TestT22TamperingDisguisedAsACrash",
		"A flipped bit past the last checkpoint is quarantined like a torn write, and the log verifies without it."},
	{"T-23", resPartial, "attack", "TestT23DeleteLeadingSegments",
		"Leading segments deleted down to a boundary verify, as a prune does."},
}

// threats reads the T-nn headings of docs/THREAT-MODEL.md, with their titles.
func threats(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open("../docs/THREAT-MODEL.md")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	heading := regexp.MustCompile(`^### (T-\d\d) — (.+)$`)
	got := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := heading.FindStringSubmatch(sc.Text()); m != nil {
			got[m[1]] = m[2]
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) < 20 {
		t.Fatalf("read %d threats from the threat model; the parser is looking at the wrong thing", len(got))
	}
	return got
}

// Every threat of the threat model has exactly one entry, and every entry is
// a threat the model names: CI fails when a threat has no test (#47).
//
// Seen failing with T-23 removed from the registry, and with a heading for a
// new threat added to the threat model.
func TestEveryThreatHasATest(t *testing.T) {
	model := threats(t)
	seen := map[string]bool{}
	for _, e := range registry {
		if seen[e.threat] {
			t.Errorf("%s is in the registry twice", e.threat)
		}
		seen[e.threat] = true
		if _, ok := model[e.threat]; !ok {
			t.Errorf("%s is in the registry and not in the threat model", e.threat)
		}
	}
	for id := range model {
		if !seen[id] {
			t.Errorf("%s has no test in the attack suite", id)
		}
	}
}

// Every test the registry names exists in the package it names, so a renamed
// or deleted test cannot leave a threat silently uncovered.
//
// Seen failing with a test name misspelled in the registry.
func TestEveryNamedTestExists(t *testing.T) {
	checked := 0
	for _, e := range registry {
		dir := filepath.Join("..", e.pkg)
		if e.pkg == "attack" {
			dir = "."
		}
		files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no test files in %s", e.threat, dir)
		}
		found := false
		for _, file := range files {
			b, err := os.ReadFile(file) // #nosec G304 -- a file of this module
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "\nfunc "+e.test+"(t *testing.T) {") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: no func %s in %s", e.threat, e.test, dir)
		}
		checked++
	}
	if checked != len(registry) || checked == 0 {
		t.Fatalf("checked %d, want %d", checked, len(registry))
	}
}

const (
	tableBegin = "<!-- attack-table:begin, generated by attack/registry_test.go; run go test ./attack -run TestTheREADMETableIsCurrent -write-readme -->"
	tableEnd   = "<!-- attack-table:end -->"
)

// table renders the registry as the README's table.
func table(t *testing.T) string {
	t.Helper()
	model := threats(t)
	rows := slices.Clone(registry)
	slices.SortFunc(rows, func(a, b entry) int { return strings.Compare(a.threat, b.threat) })
	var b strings.Builder
	b.WriteString("| Threat | Result | Test | What the test shows |\n| --- | --- | --- | --- |\n")
	for _, e := range rows {
		pkg := e.pkg
		if pkg == "." {
			pkg = "tally"
		}
		fmt.Fprintf(&b, "| %s %s | %s | `%s.%s` | %s |\n", e.threat, model[e.threat], e.result, pkg, e.test, e.shows)
	}
	return b.String()
}

// The README's attack table is generated from the registry and is current: a
// changed registry or threat model fails here until the table is regenerated.
// The tests it names run in the same CI, so the table is green only if they
// pass.
//
// Seen failing with a row of the README's table edited by hand.
func TestTheREADMETableIsCurrent(t *testing.T) {
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(readme)
	i, j := strings.Index(s, tableBegin), strings.Index(s, tableEnd)
	if i < 0 || j < i {
		t.Fatalf("the README has no attack table between %q and %q", tableBegin, tableEnd)
	}
	want := s[:i+len(tableBegin)] + "\n" + table(t) + s[j:]
	if *writeREADME {
		if err := os.WriteFile("../README.md", []byte(want), 0o600); err != nil { // #nosec G703 -- the module's own README, on request
			t.Fatal(err)
		}
		return
	}
	if want != s {
		t.Fatal("the README's attack table is not current; regenerate it with -write-readme")
	}
}
