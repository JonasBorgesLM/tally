package seal

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// Shred preserves Verify, shown by a verification before and after, and
// sealed payloads under the shredded ref no longer open, while another
// subject's still do (RF-12).
//
// Seen failing with the removal of the ref's file skipped.
func TestShredPreservesVerifyAndOpenIsErrShredded(t *testing.T) {
	ctx := context.Background()
	v := open(t, vaultDir(t), kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	signer, err := note.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	mem := tallytest.NewMemStore()
	l, err := tally.Open(ctx, keepOpen{mem}, signer, tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]tally.SubjectRef{}
	for _, who := range []string{"alice", "bob"} {
		refs[who] = resolve(t, v, who)
		p, perr := Payload(ctx, v, l.ID(), tally.EventID(who), refs[who], []byte(who+"'s address"))
		if perr != nil {
			t.Fatal(perr)
		}
		ev := tally.Event{ID: tally.EventID(who), OccurredAt: time.Unix(1_700_000_000, 0), Actor: tally.Subject(refs[who]),
			Action: "profile.update", Outcome: tally.OutcomeSuccess, Payload: p}
		if _, err = l.Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	verify := func(when string) {
		t.Helper()
		rep, verr := tally.Verify(ctx, mem, keys, tally.WithRequireFullyAttested())
		if verr != nil || !rep.OK() || rep.Size != 3 {
			t.Fatalf("Verify %s the shred = %v, %+v", when, verr, rep)
		}
	}
	verify("before")
	if err = v.Shred(ctx, refs["alice"]); err != nil {
		t.Fatal(err)
	}
	verify("after")

	for r, rerr := range mem.Records(ctx, 1) {
		if rerr != nil {
			t.Fatal(rerr)
		}
		rv, derr := tally.DecodeRecord(r.Body)
		if derr != nil {
			t.Fatal(derr)
		}
		var ref tally.SubjectRef
		copy(ref[:], rv.SubjectRef)
		a, aerr := AAD(rv.LogID, tally.EventID(rv.EventID), ref)
		if aerr != nil {
			t.Fatal(aerr)
		}
		_, oerr := v.Open(ctx, ref, rv.Payload, a)
		switch ref {
		case refs["alice"]:
			if !errors.Is(oerr, tally.ErrShredded) {
				t.Errorf("Open of alice's payload after the shred = %v, want tally.ErrShredded", oerr)
			}
		case refs["bob"]:
			if oerr != nil {
				t.Errorf("Open of bob's payload after alice's shred = %v", oerr)
			}
		}
	}
}

// Shred is idempotent: twice, or on a ref that was never made, it is nil.
func TestShredIsIdempotent(t *testing.T) {
	v := open(t, vaultDir(t), kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	ref := resolve(t, v, "alice")
	for range 2 {
		if err := v.Shred(context.Background(), ref); err != nil {
			t.Fatalf("Shred = %v", err)
		}
	}
	if err := v.Shred(context.Background(), tally.SubjectRef{1, 2, 3}); err != nil {
		t.Fatalf("Shred of an unknown ref = %v", err)
	}
}

// After a shred, Resolve makes a new incarnation: a different ref, which
// seals and opens, and no vault file holds the old ref in any form (ADR-0011).
func TestANewIncarnationIsUnlinked(t *testing.T) {
	dir := vaultDir(t)
	v := open(t, dir, kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	old := resolve(t, v, "alice")
	if err := v.Shred(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	fresh := resolve(t, v, "alice")
	if fresh == old {
		t.Fatal("the new incarnation has the old ref")
	}
	if again := resolve(t, v, "alice"); again != fresh {
		t.Fatal("the new incarnation is not stable")
	}
	_, payload := sealed(t, v, "alice", "ev", []byte("new"))
	a, err := AAD(testLogID(), "ev", fresh)
	if err != nil {
		t.Fatal(err)
	}
	if got, oerr := v.Open(context.Background(), fresh, payload, a); oerr != nil || string(got) != "new" {
		t.Fatalf("Open under the new incarnation = %q, %v", got, oerr)
	}

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if bytes.Contains([]byte(path), []byte(hex.EncodeToString(old[:]))) {
			t.Errorf("%s names the old ref", path)
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path) // #nosec G304 G122 -- a test's own temporary directory
		if err != nil {
			return err
		}
		if bytes.Contains(b, old[:]) {
			t.Errorf("%s holds the old ref", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A shred of an old incarnation never removes the index entry a newer one
// owns: here the old ref's file is back beside an index that names the new
// ref, as a restore of part of a backup would leave it.
//
// Seen failing with the check that the index names this ref removed.
func TestShredLeavesANewerIncarnationsIndex(t *testing.T) {
	dir := vaultDir(t)
	v := open(t, dir, kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	old := resolve(t, v, "alice")
	oldFile := filepath.Join(dir, refName(old))
	saved, err := os.ReadFile(oldFile) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(oldFile); err != nil {
		t.Fatal(err)
	}
	fresh := resolve(t, v, "alice")                            // the index now names fresh
	if err = os.WriteFile(oldFile, saved, 0o600); err != nil { // #nosec G703 -- a test's own file
		t.Fatal(err)
	}
	if err = v.Shred(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if got := resolve(t, v, "alice"); got != fresh {
		t.Fatal("shredding the old incarnation removed the new one's index")
	}
}

// recordFS records removals and syncs as "<op> <dir>/<base>".
type recordFS struct {
	fsx.FS
	ops []string
}

func short(path string) string {
	return filepath.Join(filepath.Base(filepath.Dir(path)), filepath.Base(path))
}

func (r *recordFS) Remove(name string) error {
	r.ops = append(r.ops, "remove "+short(name))
	return r.FS.Remove(name)
}

func (r *recordFS) OpenFile(name string, flag int, perm fs.FileMode) (fsx.File, error) {
	f, err := r.FS.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &recordFile{File: f, r: r, name: short(name)}, nil
}

type recordFile struct {
	fsx.File
	r    *recordFS
	name string
}

func (f *recordFile) Sync() error {
	f.r.ops = append(f.r.ops, "sync "+f.name)
	return f.File.Sync()
}

// The deletion is durable: the ref's file is removed and its directory
// fsynced, before the index entry is removed and its directory fsynced
// (ADR-0009's discipline, applied to destruction).
//
// Seen failing with the directory fsync removed from remove.
func TestShredIsDurable(t *testing.T) {
	dir := vaultDir(t)
	r := &recordFS{FS: fsx.OS{}}
	v := open(t, dir, kek(t, "a", 1), func(c *config) { c.fsys = r })
	defer func() { _ = v.Close() }()
	ref := resolve(t, v, "alice")
	b, err := os.ReadFile(filepath.Join(dir, refName(ref))) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	idx, _, _, err := decodeRef(b)
	if err != nil {
		t.Fatal(err)
	}
	r.ops = nil
	if err = v.Shred(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Base(dir)
	want := []string{
		"remove " + filepath.Join(refsDir, hex.EncodeToString(ref[:])), "sync " + filepath.Join(vault, refsDir),
		"remove " + filepath.Join(idxDir, hex.EncodeToString(idx[:])), "sync " + filepath.Join(vault, idxDir),
	}
	var got []string
	for _, op := range r.ops {
		if op[:6] == "remove" || slices.Contains(want, op) {
			got = append(got, op)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("operations %q, want, in order, %q", r.ops, want)
	}
}
