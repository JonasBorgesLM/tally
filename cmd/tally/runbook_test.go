package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/anchor"
	"github.com/JonasBorgesLM/tally/filestore"
	"github.com/JonasBorgesLM/tally/seal"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// The drills of docs/RUNBOOK.md (#50): each procedure run once, step by step,
// through the CLI where it has a command and the library where it does not,
// against real directories. The RUNBOOK cites each one as what its procedure
// was executed against. A step outside software, such as isolating a host,
// is named in the RUNBOOK and not pretended here.

// copyDir copies the regular files under src into dst, subdirectories
// included, as a backup does. A vault keeps its keys in subdirectories.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	copied := 0
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o700)
		case !d.Type().IsRegular():
			return nil
		}
		b, err := os.ReadFile(path) // #nosec G304 G122 -- a drill's own file
		if err != nil {
			return err
		}
		copied++
		return os.WriteFile(target, b, 0o600) // #nosec G703 -- a drill's own file
	})
	if err != nil {
		t.Fatal(err)
	}
	if copied == 0 {
		t.Fatalf("copied nothing from %s", src)
	}
}

// replaceDir makes dst a copy of src, as a restore from a backup does.
func replaceDir(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.RemoveAll(dst); err != nil {
		t.Fatal(err)
	}
	copyDir(t, src, dst)
}

func mustContain(t *testing.T, what, out, want string) {
	t.Helper()
	if !strings.Contains(out, want) {
		t.Fatalf("%s: want %q in the output:\n%s", what, want, out)
	}
}

// Host compromise (T-07, T-21). The attacker holds the host and the signing
// key: they roll the log back to an earlier copy, write another history over
// it with the key, and rewrite the host's anchor spool to match. Evidence is
// preserved first, the host's own anchor is shown to prove nothing, and the
// copy off the host finds the fork.
func TestDrillHostCompromise(t *testing.T) {
	root := t.TempDir()
	dir, spool, offHost := filepath.Join(root, "log"), filepath.Join(root, "spool"), filepath.Join(root, "off-host")
	key := tallytest.TestVerifierKey

	writeLog(t, dir, spool, "a", 6, true)
	copyDir(t, dir, filepath.Join(root, "earlier"))
	writeLog(t, dir, spool, "b", 6, true)
	copyDir(t, spool, offHost) // the anchor side's pull

	// The compromise.
	replaceDir(t, filepath.Join(root, "earlier"), dir)
	if err := os.RemoveAll(spool); err != nil {
		t.Fatal(err)
	}
	writeLog(t, dir, spool, "forged", 6, true)

	// Step 1: preserve the evidence before touching anything.
	bundle := filepath.Join(root, "evidence.tar")
	if _, stderr, code := cli(t, "export", "--dir", dir, "--format", "bundle", "--out", bundle,
		"--key", key, "--anchor", offHost); code != exitIntact {
		t.Fatalf("export of the evidence: status %d\n%s", code, stderr)
	}
	if out, _, code := cli(t, "bundle-check", bundle); code != exitIntact {
		t.Fatalf("bundle-check: status %d\n%s", code, out)
	}

	// Step 2: the host's own spool says nothing: it was rewritten with the log.
	if out, _, code := cli(t, "verify", "--dir", dir, "--key", key, "--anchor", spool); code != exitIntact {
		t.Fatalf("against the host's spool the forgery verifies, which is the limit the RUNBOOK states; got status %d\n%s", code, out)
	}

	// Step 3: the copy off the host finds it.
	out, _, code := cli(t, "verify", "--dir", dir, "--key", key, "--anchor", offHost)
	if code != exitViolation {
		t.Fatalf("against the off-host copy: status %d, want %d\n%s", code, exitViolation, out)
	}
	mustContain(t, "verify against the off-host copy", out, "violation ForkDetected")
}

var errDiskRefused = errors.New("drill: the disk refused the write")

// poisonObserver records Poisoned.
type poisonObserver struct {
	mu       sync.Mutex
	poisoned []error
}

func (*poisonObserver) Batch(int, time.Duration)      {}
func (*poisonObserver) AnchorPublish(error, uint64)   {}
func (*poisonObserver) DiskSpace(uint64)              {}
func (*poisonObserver) ClockRegression(time.Duration) {}
func (*poisonObserver) Recovered(int64)               {}
func (o *poisonObserver) Poisoned(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.poisoned = append(o.poisoned, err)
}

// A poisoned log (ADR-0009, R-31). A write fails; the log refuses every later
// Append; it is closed, reopened, verified, and the failed Append is retried
// with the same EventID, which records it once.
func TestDrillPoisonedLog(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	dir, spool := filepath.Join(root, "log"), filepath.Join(root, "spool")
	key := tallytest.TestVerifierKey
	a, err := anchor.NewDir(spool)
	if err != nil {
		t.Fatal(err)
	}

	s, err := filestore.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	obs := &poisonObserver{}
	// The genesis and three entries are stored; the fifth batch fails.
	l, err := tally.Open(ctx, tallytest.NewFaultyStore(s, tallytest.FailAppend(5, errDiskRefused)), signer(t), tally.WithAnchors(a),
		tally.WithObserver(obs), tally.WithMaxDelay(0), tally.WithCheckpointEvery(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if _, err = l.Append(ctx, event(fmt.Sprintf("ok-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = l.Append(ctx, event("lost")); !errors.Is(err, errDiskRefused) {
		t.Fatalf("the failing Append = %v, want the store's error", err)
	}
	if _, err = l.Append(ctx, event("after")); !errors.Is(err, tally.ErrPoisoned) {
		t.Fatalf("the next Append = %v, want ErrPoisoned", err)
	}
	if len(obs.poisoned) != 1 {
		t.Fatalf("Observer.Poisoned called %d times, want once", len(obs.poisoned))
	}

	// Step 1: close. A poisoned log signs no closing checkpoint.
	_ = l.Close()

	// Step 3: reopen, after the restart.
	s, err = filestore.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err = tally.Open(ctx, s, signer(t), tally.WithAnchors(a))
	if err != nil {
		t.Fatal(err)
	}

	// Step 4: retry what failed, with the same EventID: recorded once, as a
	// new entry; and a retry of one that was stored is a duplicate.
	rec, err := l.Append(ctx, event("lost"))
	if err != nil || rec.Duplicate || rec.Seq != 4 {
		t.Fatalf("the retried Append = %+v, %v; want seq 4, not a duplicate", rec, err)
	}
	rec, err = l.Append(ctx, event("ok-1"))
	if err != nil || !rec.Duplicate || rec.Seq != 2 {
		t.Fatalf("a retry of a stored entry = %+v, %v; want the duplicate of seq 2", rec, err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}

	// Step 5: verify against the anchor.
	out, _, code := cli(t, "verify", "--dir", dir, "--key", key, "--anchor", spool, "--require-fully-attested")
	if code != exitIntact {
		t.Fatalf("verify after the poisoned log: status %d\n%s", code, out)
	}
	mustContain(t, "verify after the poisoned log", out, "size 5\n")
}

// spaceObserver records DiskSpace and Poisoned, in order.
type spaceObserver struct {
	mu     sync.Mutex
	events []string
}

func (*spaceObserver) Batch(int, time.Duration)      {}
func (*spaceObserver) AnchorPublish(error, uint64)   {}
func (*spaceObserver) ClockRegression(time.Duration) {}
func (*spaceObserver) Recovered(int64)               {}

func (o *spaceObserver) DiskSpace(uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.events) == 0 || o.events[len(o.events)-1] != "DiskSpace" {
		o.events = append(o.events, "DiskSpace")
	}
}

func (o *spaceObserver) Poisoned(error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, "Poisoned")
}

func (o *spaceObserver) firstOf(e string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i, got := range o.events {
		if got == e {
			return i
		}
	}
	return -1
}

// smallVolumeEnv names a small, real volume for TestDrillDiskFull: a 2 MB
// tmpfs, mounted by the CI job "runbook drill on a small volume", or locally:
//
//	docker run --rm --tmpfs /small:size=2m -v "$PWD":/src -w /src golang:1.26 \
//	  sh -c 'TALLY_SMALL_VOLUME=/small go test ./cmd/tally -run TestDrillDiskFull -v'
const smallVolumeEnv = "TALLY_SMALL_VOLUME"

// A full disk (T-16), on a real volume rather than an injected filesystem:
// the Observer hears of low space before writes fail, the log poisons when
// they do, and after freeing space it reopens, recovers its torn tail,
// verifies and appends again.
func TestDrillDiskFull(t *testing.T) {
	vol := os.Getenv(smallVolumeEnv)
	if vol == "" {
		t.Skipf("%s is not set: this drill needs a small volume of its own", smallVolumeEnv)
	}
	ctx := t.Context()
	dir := filepath.Join(vol, "log")
	spool := filepath.Join(t.TempDir(), "spool") // the anchor is never on the log's volume
	key := tallytest.TestVerifierKey
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) // #nosec G703 -- under the volume the drill was given

	// Something else on the volume, which step 2 removes.
	filler := filepath.Join(vol, "filler")
	t.Cleanup(func() { _ = os.Remove(filler) })                              // #nosec G703 -- the drill's own file
	if err := os.WriteFile(filler, make([]byte, 1<<20), 0o600); err != nil { // #nosec G703 -- the drill's own file
		t.Fatal(err)
	}

	a, err := anchor.NewDir(spool)
	if err != nil {
		t.Fatal(err)
	}
	open := func(obs tally.Observer) *tally.Log {
		t.Helper()
		s, serr := filestore.Open(ctx, dir, filestore.WithFreeSpaceThreshold(256<<10))
		if serr != nil {
			t.Fatal(serr)
		}
		l, lerr := tally.Open(ctx, s, signer(t), tally.WithAnchors(a), tally.WithObserver(obs), tally.WithMaxDelay(0))
		if lerr != nil {
			t.Fatal(lerr)
		}
		return l
	}

	obs := &spaceObserver{}
	l := open(obs)
	appended := 0
	for ; ; appended++ {
		if appended > 1_000_000 {
			t.Fatal("a million entries and the volume is not full: it is not the small volume the drill needs")
		}
		_, err = l.Append(ctx, event(fmt.Sprintf("e-%d", appended)))
		if err != nil {
			break
		}
	}
	t.Logf("the failing Append: %v", err)
	ds, p := obs.firstOf("DiskSpace"), obs.firstOf("Poisoned")
	if ds < 0 || p < 0 || ds > p {
		t.Fatalf("observer events %v: want DiskSpace before Poisoned", obs.events)
	}
	t.Logf("%d entries appended before the volume filled; observer events %v", appended, obs.events)

	// Step 1: close.
	_ = l.Close()
	// Step 2: free space.
	if err = os.Remove(filler); err != nil { // #nosec G703 -- the drill's own file
		t.Fatal(err)
	}
	// Step 3: reopen; the torn tail, if the failed write left one, is quarantined.
	l = open(&spaceObserver{})
	if _, err = l.Append(ctx, event("after-the-disk-was-freed")); err != nil {
		t.Fatalf("Append after freeing space: %v", err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	// Step 4: verify against the anchor.
	out, _, code := cli(t, "verify", "--dir", dir, "--key", key, "--anchor", spool, "--require-fully-attested")
	if code != exitIntact {
		t.Fatalf("verify after the disk was freed: status %d\n%s", code, out)
	}
	mustContain(t, "verify after the disk was freed", out, fmt.Sprintf("size %d\n", appended+2))
}

// Prune (ADR-0012). The segments to remove are archived first, as a
// bundle checked against its manifest; the prune is at a checkpoint the
// anchor holds; the log verifies against the anchor after it.
func TestDrillPrune(t *testing.T) {
	dir, anchorDir, _, anchored := prunableLog(t)
	key := tallytest.TestVerifierKey
	root := t.TempDir()

	// Step 1: archive, and check the archive.
	archive := filepath.Join(root, "archive.tar")
	if _, stderr, code := cli(t, "export", "--dir", dir, "--format", "bundle", "--out", archive,
		"--key", key, "--anchor", anchorDir); code != exitIntact {
		t.Fatalf("export: status %d\n%s", code, stderr)
	}
	if out, _, code := cli(t, "bundle-check", archive); code != exitIntact {
		t.Fatalf("bundle-check: status %d\n%s", code, out)
	}

	// Step 2: prune, the log closed, at an anchored checkpoint.
	before := segments(t, dir)
	out, stderr, code := cli(t, "prune", "--dir", dir, "--key", key, "--anchor", anchorDir,
		"--checkpoint", writeCheckpoint(t, anchored))
	if code != exitIntact {
		t.Fatalf("prune: status %d\n%s%s", code, out, stderr)
	}
	if after := segments(t, dir); len(after) >= len(before) {
		t.Fatalf("segments %v -> %v: nothing was pruned", before, after)
	}

	// Step 3: verify against the anchor.
	if out, _, code = cli(t, "verify", "--dir", dir, "--key", key, "--anchor", anchorDir); code != exitIntact {
		t.Fatalf("verify after the prune: status %d\n%s", code, out)
	}
	// The archive still holds what was pruned, and still checks.
	if out, _, code = cli(t, "bundle-check", archive); code != exitIntact {
		t.Fatalf("bundle-check after the prune: status %d\n%s", code, out)
	}
}

func drillKEK(t *testing.T, id string, b byte) seal.KEK {
	t.Helper()
	k, err := seal.NewLocalKEK(id, bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func openVault(t *testing.T, dir string, kek seal.KEK) *seal.FileVault {
	t.Helper()
	v, err := seal.OpenFileVault(context.Background(), dir, kek)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// sealedPayloads reads the log in dir and returns each sealed payload's
// bytes and AAD, by subject ref.
func sealedPayloads(t *testing.T, dir string) map[tally.SubjectRef][2][]byte {
	t.Helper()
	r, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[tally.SubjectRef][2][]byte{}
	for rec, rerr := range r.Records(context.Background(), 1) {
		if rerr != nil {
			t.Fatal(rerr)
		}
		rv, derr := tally.DecodeRecord(rec.Body)
		if derr != nil {
			t.Fatal(derr)
		}
		if len(rv.SubjectRef) == 0 {
			continue
		}
		var ref tally.SubjectRef
		copy(ref[:], rv.SubjectRef)
		aad, aerr := seal.AAD(rv.LogID, tally.EventID(rv.EventID), ref)
		if aerr != nil {
			t.Fatal(aerr)
		}
		got[ref] = [2][]byte{rv.Payload, aad}
	}
	return got
}

const shredAction = "subject.shred"

// Shredding a subject, and vault backups (RF-12, T-19, T-20). A shred is
// recorded in the log by ref; a backup from before it undoes it, until the
// shreds the log records are applied again after the restore; and a KEK
// rotation with the old KEK destroyed makes an old backup unreadable.
func TestDrillShredAndVaultBackups(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	dir, vaultDir, backup := filepath.Join(root, "log"), filepath.Join(root, "vault"), filepath.Join(root, "vault-backup")
	key := tallytest.TestVerifierKey
	kek1 := drillKEK(t, "kek-1", 1)

	v := openVault(t, vaultDir, kek1)
	s, err := filestore.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tally.Open(ctx, s, signer(t))
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]tally.SubjectRef{}
	for _, who := range []string{"alice@example.com", "bob@example.com"} {
		ref, rerr := v.Resolve(ctx, []byte(who))
		if rerr != nil {
			t.Fatal(rerr)
		}
		refs[who] = ref
		id := tally.EventID("login-" + hex.EncodeToString(ref[:4]))
		p, perr := seal.Payload(ctx, v, l.ID(), id, ref, []byte("ip 203.0.113.7"))
		if perr != nil {
			t.Fatal(perr)
		}
		if _, err = l.Append(ctx, tally.Event{ID: id, OccurredAt: time.Unix(1_700_000_000, 0), Actor: tally.Subject(ref),
			Action: "user.login", Outcome: tally.OutcomeSuccess, Payload: p}); err != nil {
			t.Fatal(err)
		}
	}
	alice, bob := refs["alice@example.com"], refs["bob@example.com"]

	// A vault backup, taken before the request.
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	copyDir(t, vaultDir, backup)
	v = openVault(t, vaultDir, kek1)

	// Shredding, steps 2 and 3: shred, and record it by ref, without the identifier.
	if err = v.Shred(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Append(ctx, tally.Event{ID: "shred-req-1", OccurredAt: time.Unix(1_700_000_100, 0), Actor: tally.System(),
		Action: shredAction, Resource: "subject/" + hex.EncodeToString(alice[:]), Outcome: tally.OutcomeSuccess}); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	// Step 4: the log still verifies.
	if out, _, code := cli(t, "verify", "--dir", dir, "--key", key, "--require-fully-attested"); code != exitIntact {
		t.Fatalf("verify after the shred: status %d\n%s", code, out)
	}
	payloads := sealedPayloads(t, dir)
	openAs := func(v *seal.FileVault, ref tally.SubjectRef) error {
		_, oerr := v.Open(ctx, ref, payloads[ref][0], payloads[ref][1])
		return oerr
	}
	if err = openAs(v, alice); !errors.Is(err, tally.ErrShredded) {
		t.Fatalf("alice's payload after the shred: %v, want ErrShredded", err)
	}

	// The limit: the backup from before the shred still opens it.
	old := openVault(t, backup, kek1)
	if err = openAs(old, alice); err != nil {
		t.Fatalf("the pre-shred backup no longer opens alice's payload (%v): the RUNBOOK's warning would be wrong", err)
	}
	_ = old.Close()

	// Restoring a vault backup: restore, then apply again every shred the log
	// records, read through tally export.
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	replaceDir(t, backup, vaultDir)
	v = openVault(t, vaultDir, kek1)
	defer func() { _ = v.Close() }()
	if err = openAs(v, alice); err != nil {
		t.Fatalf("the restored vault should open alice's payload until the shreds are applied again: %v", err)
	}
	stdout, stderr, code := cli(t, "export", "--dir", dir)
	if code != exitIntact {
		t.Fatalf("export: status %d\n%s", code, stderr)
	}
	reapplied := 0
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		var line struct {
			Action, Resource string
		}
		if err = json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		if line.Action != shredAction {
			continue
		}
		b, herr := hex.DecodeString(strings.TrimPrefix(line.Resource, "subject/"))
		if herr != nil || len(b) != len(tally.SubjectRef{}) {
			t.Fatalf("a shred record names no ref: %q", line.Resource)
		}
		if err = v.Shred(ctx, tally.SubjectRef(b)); err != nil {
			t.Fatal(err)
		}
		reapplied++
	}
	if reapplied != 1 {
		t.Fatalf("applied %d shreds again, want 1", reapplied)
	}
	if err = openAs(v, alice); !errors.Is(err, tally.ErrShredded) {
		t.Fatalf("alice's payload after the shreds were applied again: %v, want ErrShredded", err)
	}
	if err = openAs(v, bob); err != nil {
		t.Fatalf("bob's payload after alice's shred was applied again: %v", err)
	}

	// Narrowing what the medium keeps: rotate the KEK and destroy the old one.
	// The backup, wrapped under the destroyed KEK, opens under no other.
	if err = v.RotateKEK(ctx, drillKEK(t, "kek-2", 2)); err != nil {
		t.Fatal(err)
	}
	if err = openAs(v, bob); err != nil {
		t.Fatalf("bob's payload after the KEK rotation: %v", err)
	}
	if _, err = seal.OpenFileVault(ctx, backup, drillKEK(t, "kek-2", 2)); err == nil {
		t.Fatal("the old backup opened under the new KEK")
	}
}

// dropClosed is an anchor that never receives a closing checkpoint: what the
// anchor side sees of a host that died, or lost its link, while running.
type dropClosed struct{ tally.Anchor }

func (d dropClosed) Publish(ctx context.Context, cp tally.SignedCheckpoint) error {
	if bytes.Contains(cp, []byte("\nclosed\n")) {
		return nil
	}
	return d.Anchor.Publish(ctx, cp)
}

// Monitoring off the host (T-15). The two checks the RUNBOOK gives the anchor
// side: that a checkpoint arrived recently, from the spool files' arrival
// times; and that the anchored heartbeats have no gap. A host that stopped
// while running fails both; one that closed cleanly passes the heartbeat.
func TestDrillMonitoringOffTheHost(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	dir, died, clean := filepath.Join(root, "log"), filepath.Join(root, "anchor-died"), filepath.Join(root, "anchor-clean")
	key := tallytest.TestVerifierKey
	aDied, err := anchor.NewDir(died)
	if err != nil {
		t.Fatal(err)
	}
	aClean, err := anchor.NewDir(clean)
	if err != nil {
		t.Fatal(err)
	}

	// Checkpoints a minute apart, an hour ago and more: the signer's clock.
	clock := tallytest.NewFixedClock(time.Now().Add(-2 * time.Hour).UTC())
	s, err := filestore.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tally.Open(ctx, s, signer(t), tally.WithClock(clock), tally.WithCheckpointEvery(0, 0),
		tally.WithAnchors(dropClosed{aDied}, aClean))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		clock.Advance(time.Minute)
		if _, err = l.Append(ctx, event(fmt.Sprintf("m-%d", i))); err != nil {
			t.Fatal(err)
		}
		if _, err = l.Checkpoint(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}

	// Check 1, arrival: a checkpoint file newer than the window. The spool was
	// just written, so this one passes; aged an hour, it alerts.
	recent := func(spool string) bool {
		t.Helper()
		out, ferr := exec.CommandContext(ctx, "find", spool, "-name", "*.note", "-mmin", "-5").Output() // #nosec G204 -- fixed arguments
		if ferr != nil {
			t.Fatal(ferr)
		}
		return len(bytes.TrimSpace(out)) > 0
	}
	if !recent(died) {
		t.Fatal("the arrival check found no recent checkpoint in a spool written just now")
	}
	age(t, died, time.Hour)
	if recent(died) {
		t.Fatal("the arrival check found a recent checkpoint in a spool aged an hour")
	}

	// Check 2, heartbeat: the host that died has a gap since its last open
	// checkpoint; the one that closed cleanly has none.
	out, _, code := cli(t, "verify", "--dir", dir, "--key", key, "--anchor", died, "--heartbeat", "1m", "--tolerance", "30s")
	if code != exitViolation {
		t.Fatalf("heartbeat against the anchor of a host that died: status %d\n%s", code, out)
	}
	mustContain(t, "heartbeat of a host that died", out, "violation HeartbeatGap")
	if out, _, code = cli(t, "verify", "--dir", dir, "--key", key, "--anchor", clean, "--heartbeat", "1m", "--tolerance", "30s"); code != exitIntact {
		t.Fatalf("heartbeat against the anchor of a clean close: status %d\n%s", code, out)
	}
}

// age sets every file in dir to have been modified d ago.
func age(t *testing.T, dir string, d time.Duration) {
	t.Helper()
	when := time.Now().Add(-d)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err = os.Chtimes(filepath.Join(dir, e.Name()), when, when); err != nil {
			t.Fatal(err)
		}
	}
}

// "Upgrading from v0.1" (#60): a log a v0.1 writer wrote, as its bytes
// (testdata/vectors/segments.json), with its tally-chain/v1 checkpoint in the
// anchor. The v0.2 writer reopens it, appends and closes; it stores and
// publishes the new pairs beside the old checkpoint, nothing stored is
// rewritten, and the log verifies against the anchor, all of it attested.
func TestDrillUpgradeFromV01(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dir, anchorDir := filepath.Join(root, "log"), filepath.Join(root, "anchor")
	for _, d := range []string{dir, anchorDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// The v0.1 log, byte for byte, and its checkpoint in the anchor.
	raw, err := os.ReadFile("../../testdata/vectors/segments.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec struct {
		Files []struct{ Name, Hex string } `json:"files"`
	}
	if err = json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, f := range vec.Files {
		b, herr := hex.DecodeString(f.Hex)
		if herr != nil {
			t.Fatal(herr)
		}
		before[f.Name] = b
		if err = os.WriteFile(filepath.Join(dir, f.Name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, err := anchor.NewDir(anchorDir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := filestore.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	for cp, cerr := range r.Checkpoints(ctx) {
		if cerr != nil {
			t.Fatal(cerr)
		}
		if !bytes.Contains(cp, []byte("\ntally-chain/v1\n")) {
			t.Fatalf("the vector's checkpoint is not v0.1's:\n%s", cp)
		}
		if err = a.Publish(ctx, cp); err != nil {
			t.Fatal(err)
		}
	}

	// The v0.2 writer reopens it, appends and closes, publishing to the anchor.
	s, err := filestore.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tally.Open(ctx, s, signer(t), tally.WithAnchors(a), tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		ev := tally.Event{ID: tally.EventID(fmt.Sprintf("upgrade-%d", i)), OccurredAt: time.Unix(1_800_000_000, 0),
			Actor: tally.System(), Action: "user.login", Outcome: tally.OutcomeSuccess}
		if _, err = l.Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}

	// Nothing v0.1 stored was rewritten: segment 0 is the same bytes.
	seg0, err := os.ReadFile(filepath.Join(dir, "0000000000000000.tlog")) // #nosec G304 -- a drill's own file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seg0, before["0000000000000000.tlog"]) {
		t.Fatal("the v0.2 writer rewrote segment 0")
	}
	kinds := map[string]int{}
	for cp, cerr := range a.Checkpoints(ctx) {
		if cerr != nil {
			t.Fatal(cerr)
		}
		switch {
		case bytes.Contains(cp, []byte("\ntally-chain/v1\n")):
			kinds["v0.1"]++
		case bytes.Contains(cp, []byte("\ntally-heartbeat/v1\n")):
			kinds["heartbeat"]++
		case isTlog(cp):
			kinds["tlog"]++
		}
	}
	if kinds["v0.1"] != 1 || kinds["heartbeat"] != 1 || kinds["tlog"] != 1 {
		t.Fatalf("the anchor holds %v, want the v0.1 checkpoint and one new pair", kinds)
	}

	out, stderr, code := cli(t, "verify", "--dir", dir, "--key", tallytest.TestVerifierKey, "--anchor", anchorDir,
		"--require-fully-attested")
	if code != exitIntact || line(t, out, "attested") != "8" {
		t.Fatalf("verify: status %d\n%s%s", code, out, stderr)
	}
	if _, _, code = cli(t, "checkpoint", "--dir", dir, "--key", tallytest.TestVerifierKey, "--tlog"); code != exitIntact {
		t.Fatalf("checkpoint --tlog after the upgrade: status %d", code)
	}
}
