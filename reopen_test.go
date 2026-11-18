package tally_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// fixedLog writes a log to a fresh MemStore with a fixed random source and
// clock, so two such logs share a genesis and diverge only where their ids
// do: a host rewriting history from a point, without the key, since records
// are not signed. It checkpoints after the entries numbered in cpAt, and
// closes, which signs a closing checkpoint.
func fixedLog(t *testing.T, signer tally.Signer, ids []string, cpAt ...int) *tallytest.MemStore {
	t.Helper()
	ctx := context.Background()
	mem := tallytest.NewMemStore()
	clock := tallytest.NewFixedClock(time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC))
	l, err := tally.Open(ctx, keepOpen{mem}, signer, tally.WithCheckpointEvery(0, 0),
		tally.WithRand(bytes.NewReader(bytes.Repeat([]byte{7}, 16))), tally.WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		clock.Advance(time.Second)
		if _, err = l.Append(ctx, event(id)); err != nil {
			t.Fatal(err)
		}
		for _, at := range cpAt {
			if at == i+1 {
				if _, err = l.Checkpoint(ctx); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	return mem
}

func ids(prefix string, from, to int) []string {
	var out []string
	for i := from; i < to; i++ {
		out = append(out, fmt.Sprintf("%s%d", prefix, i))
	}
	return out
}

// spliced is a store holding records' records and checkpoints' checkpoints,
// or none when checkpoints is nil: what a host with write access and no key
// leaves behind.
func spliced(t *testing.T, records, checkpoints *tallytest.MemStore) *tallytest.MemStore {
	t.Helper()
	ctx := context.Background()
	out := tallytest.NewMemStore()
	var recs []tally.Record
	for r, err := range records.Records(ctx, 0) {
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if err := out.AppendBatch(ctx, recs); err != nil {
		t.Fatal(err)
	}
	if checkpoints != nil {
		for cp, err := range checkpoints.Checkpoints(ctx) {
			if err != nil {
				t.Fatal(err)
			}
			if err = out.PutCheckpoint(ctx, cp); err != nil {
				t.Fatal(err)
			}
		}
	}
	return out
}

// A log rewritten from entry 3 by someone without the key, beside its own
// signed checkpoints, is refused on reopen: the writer would otherwise sign
// its next checkpoint over a history its last one contradicts (audit A-01).
// With the checkpoints deleted as well, the rewrite cannot be told here from
// a log that never had any, and Open accepts it: that limit is T-06's, and
// only an anchor shows it.
//
// Seen failing with the comparison in load removed: Open accepted the
// rewritten log beside its checkpoints.
func TestReopenRefusesALogItsCheckpointContradicts(t *testing.T) {
	honest := fixedLog(t, testOrigin, ids("a", 0, 10), 5)
	forged := fixedLog(t, testOrigin, append(ids("a", 0, 3), ids("b", 3, 10)...))

	_, err := tally.Open(context.Background(), keepOpen{spliced(t, forged, honest)}, testOrigin)
	if !errors.Is(err, tally.ErrStoredCheckpointMismatch) {
		t.Fatalf("Open of a rewritten log beside its own checkpoints = %v, want ErrStoredCheckpointMismatch", err)
	}

	l, err := tally.Open(context.Background(), keepOpen{spliced(t, forged, nil)}, testOrigin)
	if err != nil {
		t.Fatalf("the limit: with its checkpoints deleted, the rewrite opens (T-06); got %v", err)
	}
	_ = l.Close()
}

// A log cut below its last stored checkpoint is refused, whatever the store:
// filestore's recovery refuses it too, a MemStore did not (audit A-01).
func TestReopenRefusesALogBelowItsCheckpoint(t *testing.T) {
	honest := fixedLog(t, testOrigin, ids("a", 0, 10), 5)
	short := fixedLog(t, testOrigin, ids("a", 0, 3))
	_, err := tally.Open(context.Background(), keepOpen{spliced(t, short, honest)}, testOrigin)
	if !errors.Is(err, tally.ErrStoredCheckpointMismatch) {
		t.Fatalf("Open of a log below its checkpoint = %v, want ErrStoredCheckpointMismatch", err)
	}
}

// A last checkpoint that names this log's key with a signature that key did
// not make is refused, even when its head agrees: its content is not this
// key's word.
//
// Seen failing with the signature comparison removed.
func TestReopenRefusesAForgedSignatureUnderItsKey(t *testing.T) {
	ctx := context.Background()
	honest := fixedLog(t, testOrigin, ids("a", 0, 4))
	var cps []tally.SignedCheckpoint
	for cp, err := range honest.Checkpoints(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		cps = append(cps, cp)
	}
	if len(cps) == 0 {
		t.Fatal("no checkpoint to forge")
	}
	last := cps[len(cps)-1]
	// The signature line is "<prefix><name> <base64(key id || signature)>":
	// flip a bit of the signature itself, and re-encode, so the line still
	// parses and names this log's key.
	sp := bytes.LastIndexByte(last[:len(last)-1], ' ')
	raw, err := base64.StdEncoding.DecodeString(string(last[sp+1 : len(last)-1]))
	if err != nil || len(raw) != 68 {
		t.Fatalf("the signature line does not decode: %v", err)
	}
	raw[10] ^= 0x01
	forged := append(bytes.Clone(last[:sp+1]), base64.StdEncoding.EncodeToString(raw)+"\n"...)
	out := spliced(t, honest, nil)
	for _, cp := range cps[:len(cps)-1] {
		if err = out.PutCheckpoint(ctx, cp); err != nil {
			t.Fatal(err)
		}
	}
	if err = out.PutCheckpoint(ctx, forged); err != nil {
		t.Fatal(err)
	}
	_, err = tally.Open(ctx, keepOpen{out}, testOrigin)
	if !errors.Is(err, tally.ErrStoredCheckpointMismatch) {
		t.Fatalf("Open with a forged signature under its own key = %v, want ErrStoredCheckpointMismatch", err)
	}
}

// After a rotation, the last stored checkpoint is the old key's: its head is
// compared, its signature cannot be, and an honest log opens under the new
// key with the same origin.
func TestReopenAfterARotation(t *testing.T) {
	newSkey, _, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0xB1}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	honest := fixedLog(t, testOrigin, ids("a", 0, 4), 2)
	l, err := tally.Open(context.Background(), keepOpen{honest}, mustSigner(newSkey))
	if err != nil {
		t.Fatalf("Open under the new key after a rotation: %v", err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
}
