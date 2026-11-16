package seal

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

var writeVectors = flag.Bool("write-vectors", false, "regenerate testdata/vectors/seal.json (review the diff before committing)")

func testLogID() tally.LogID {
	var id tally.LogID
	for i := range id {
		id[i] = byte(i)
	}
	return id
}

// sealed resolves an identifier and seals plaintext for event ev.
func sealed(t *testing.T, v *FileVault, who, ev string, plaintext []byte) (ref tally.SubjectRef, payload []byte) {
	t.Helper()
	ref = resolve(t, v, who)
	a, err := AAD(testLogID(), tally.EventID(ev), ref)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err = v.Seal(context.Background(), ref, plaintext, a); err != nil {
		t.Fatal(err)
	}
	return ref, payload
}

// A payload opens with its ref and AAD, in SPEC §4's format; two seals of one
// plaintext differ, since each nonce is random (RS-12).
func TestSealAndOpen(t *testing.T) {
	v := open(t, vaultDir(t), kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	plain := []byte("cpf=123.456.789-00")
	ref, s := sealed(t, v, "alice", "ev-1", plain)
	if s[0] != sealFormat || len(s) != minSealedLen+len(plain) {
		t.Fatalf("payload of %d bytes, format %#x", len(s), s[0])
	}
	a, err := AAD(testLogID(), "ev-1", ref)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Open(context.Background(), ref, s, a)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	_, again := sealed(t, v, "alice", "ev-1", plain)
	if bytes.Equal(again, s) {
		t.Fatal("two seals of one plaintext are equal: the nonce is not random")
	}
}

// A payload opens only with every AAD field as it was sealed: one test per
// field (RS-12, T-19).
//
// Seen failing with the AAD passed to Seal and Open replaced by nil.
func TestAChangedAADFieldFailsToOpen(t *testing.T) {
	v := open(t, vaultDir(t), kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	ref, s := sealed(t, v, "alice", "ev-1", []byte("secret"))
	otherLog := testLogID()
	otherLog[0] ^= 1
	otherRef := ref
	otherRef[15] ^= 1
	cases := []struct {
		name string
		aad  func() ([]byte, error)
	}{
		{"log_id", func() ([]byte, error) { return AAD(otherLog, "ev-1", ref) }},
		{"event_id", func() ([]byte, error) { return AAD(testLogID(), "ev-2", ref) }},
		{"subject_ref", func() ([]byte, error) { return AAD(testLogID(), "ev-1", otherRef) }},
		{"the tag", func() ([]byte, error) {
			a, err := AAD(testLogID(), "ev-1", ref)
			a[4] ^= 1 // the first byte of "tally/v1/seal", after its length prefix
			return a, err
		}},
	}
	ran := 0
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ran++
			a, err := c.aad()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Open(context.Background(), ref, s, a); !errors.Is(err, ErrOpen) {
				t.Fatalf("Open with another %s = %v, want ErrOpen", c.name, err)
			}
		})
	}
	if ran != len(cases) {
		t.Fatalf("ran %d, want %d", ran, len(cases))
	}
}

// Length prefixes keep the boundary between event_id and subject_ref fixed:
// moving a byte from one to the other changes the AAD, though the plain
// concatenation stays the same, and the payload no longer opens (RS-19).
//
// Seen failing with aad concatenating event_id and subject_ref without their
// length prefixes.
func TestAShiftedBoundaryFails(t *testing.T) {
	log := testLogID()
	ev := []byte("ev-1")
	ref := bytes.Repeat([]byte{0x5A}, 16)
	shiftedEv := append(append([]byte(nil), ev...), ref[0])
	shiftedRef := ref[1:]
	if !bytes.Equal(append(append([]byte(nil), ev...), ref...), append(append([]byte(nil), shiftedEv...), shiftedRef...)) {
		t.Fatal("the test meant the plain concatenations to be equal")
	}
	a, err := aad(log[:], ev, ref)
	if err != nil {
		t.Fatal(err)
	}
	b, err := aad(log[:], shiftedEv, shiftedRef)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("shifting a byte from subject_ref to event_id leaves the AAD unchanged")
	}
	dek := bytes.Repeat([]byte{7}, 32)
	s, err := sealWith(dek, make([]byte, nonceLen), []byte("secret"), a)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := newGCM(dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gcm.Open(nil, s[1:1+nonceLen], s[1+nonceLen:], b); err == nil {
		t.Fatal("a payload sealed under one boundary opened under the shifted one")
	}
}

// A payload opens under no other subject's DEK, and an altered payload does
// not open.
func TestAnotherSubjectOrAnAlteredPayloadFails(t *testing.T) {
	v := open(t, vaultDir(t), kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	ref, s := sealed(t, v, "alice", "ev-1", []byte("secret"))
	bob := resolve(t, v, "bob")
	aBob, err := AAD(testLogID(), "ev-1", bob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Open(context.Background(), bob, s, aBob); !errors.Is(err, ErrOpen) {
		t.Errorf("alice's payload under bob's DEK = %v, want ErrOpen", err)
	}
	a, err := AAD(testLogID(), "ev-1", ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 1, 13, len(s) - 1} { // format, nonce, ciphertext, tag
		altered := bytes.Clone(s)
		altered[i] ^= 1
		if _, err := v.Open(context.Background(), ref, altered, a); !errors.Is(err, ErrOpen) {
			t.Errorf("byte %d altered: Open = %v, want ErrOpen", i, err)
		}
	}
	if _, err := v.Open(context.Background(), ref, s[:minSealedLen-1], a); !errors.Is(err, ErrOpen) {
		t.Errorf("a short payload: Open = %v, want ErrOpen", err)
	}
}

// Sealing or opening under a ref whose DEK is gone is tally.ErrShredded
// (RF-12). Shred itself is #45; here the DEK's file is removed as it does.
//
// Seen failing with the mapping of a missing DEK to ErrShredded removed.
func TestAShreddedRefIsErrShredded(t *testing.T) {
	dir := vaultDir(t)
	v := open(t, dir, kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	ref, s := sealed(t, v, "alice", "ev-1", []byte("secret"))
	if err := os.Remove(filepath.Join(dir, refName(ref))); err != nil {
		t.Fatal(err)
	}
	a, err := AAD(testLogID(), "ev-1", ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Open(context.Background(), ref, s, a); !errors.Is(err, tally.ErrShredded) {
		t.Errorf("Open = %v, want tally.ErrShredded", err)
	}
	if _, err := v.Seal(context.Background(), ref, []byte("more"), a); !errors.Is(err, tally.ErrShredded) {
		t.Errorf("Seal = %v, want tally.ErrShredded", err)
	}
}

// A sealed payload goes into a Log through Payload, verifies with no DEK, and
// opens from the stored record with the AAD rebuilt from its fields.
func TestPayloadInALog(t *testing.T) {
	ctx := context.Background()
	v := open(t, vaultDir(t), kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	signer, err := note.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	mem := tallytest.NewMemStore()
	l, err := tally.Open(ctx, keepOpen{mem}, signer, tally.WithCheckpointEvery(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	ref := resolve(t, v, "alice")
	p, err := Payload(ctx, v, l.ID(), "ev-1", ref, []byte("alice's address"))
	if err != nil {
		t.Fatal(err)
	}
	ev := tally.Event{ID: "ev-1", OccurredAt: time.Unix(1_700_000_000, 0), Actor: tally.Subject(ref),
		Action: "profile.update", Outcome: tally.OutcomeSuccess, Payload: p}
	if _, err = l.Append(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	keys, err := tally.NewVerifiers(tallytest.TestVerifierKey)
	if err != nil {
		t.Fatal(err)
	}
	if rep, verr := tally.Verify(ctx, mem, keys); verr != nil || !rep.OK() {
		t.Fatalf("Verify = %v, %+v", verr, rep)
	}
	var stored tally.RecordView
	for r, err := range mem.Records(ctx, 1) {
		if err != nil {
			t.Fatal(err)
		}
		if stored, err = tally.DecodeRecord(r.Body); err != nil {
			t.Fatal(err)
		}
	}
	var sref tally.SubjectRef
	copy(sref[:], stored.SubjectRef)
	a, err := AAD(stored.LogID, tally.EventID(stored.EventID), sref)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Open(ctx, sref, stored.Payload, a)
	if err != nil || string(got) != "alice's address" {
		t.Fatalf("Open of the stored payload = %q, %v", got, err)
	}
}

// keepOpen lets a test read a MemStore after the Log closes it.
type keepOpen struct{ tally.Store }

func (keepOpen) Close() error { return nil }

const sealVectorsPath = "../testdata/vectors/seal.json"

type sealVector struct {
	Comment    string `json:"comment"`
	DEK        string `json:"dek_hex"`
	Nonce      string `json:"nonce_hex"`
	LogID      string `json:"log_id_hex"`
	EventID    string `json:"event_id_hex"`
	SubjectRef string `json:"subject_ref_hex"`
	Plaintext  string `json:"plaintext_hex"`
	AAD        string `json:"aad_hex"`
	Payload    string `json:"payload_hex"`
}

// The published sealing vector (SPEC §4, §8): a fixed DEK and nonce over the
// sealed entry of records.json's log_id, event_id and subject_ref. The AAD
// and payload were also recomputed outside Go.
func TestSealVector(t *testing.T) {
	raw, err := os.ReadFile("../testdata/vectors/records.json")
	if err != nil {
		t.Fatal(err)
	}
	var recs struct {
		Records []struct {
			Entry *struct {
				LogID       string `json:"log_id_hex"`
				EventID     string `json:"event_id_hex"`
				PayloadKind uint8  `json:"payload_kind"`
				SubjectRef  string `json:"subject_ref_hex"`
			} `json:"entry"`
		} `json:"records"`
	}
	if err = json.Unmarshal(raw, &recs); err != nil {
		t.Fatal(err)
	}
	vec := sealVector{
		Comment: "tally SPEC v1 sealing vector: a FIXED DEK and nonce, for checking implementations only. " +
			"log_id, event_id and subject_ref are records.json's sealed entry's. See README.md.",
		DEK:       hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		Nonce:     "000102030405060708090a0b",
		Plaintext: hex.EncodeToString([]byte("alice@example.com changed her address")),
	}
	for _, r := range recs.Records {
		if r.Entry != nil && r.Entry.PayloadKind == 2 {
			vec.LogID, vec.EventID, vec.SubjectRef = r.Entry.LogID, r.Entry.EventID, r.Entry.SubjectRef
		}
	}
	if vec.SubjectRef == "" {
		t.Fatal("records.json has no sealed entry")
	}
	unhex := func(s string) []byte {
		b, derr := hex.DecodeString(s)
		if derr != nil {
			t.Fatal(derr)
		}
		return b
	}
	a, err := aad(unhex(vec.LogID), unhex(vec.EventID), unhex(vec.SubjectRef))
	if err != nil {
		t.Fatal(err)
	}
	s, err := sealWith(unhex(vec.DEK), unhex(vec.Nonce), unhex(vec.Plaintext), a)
	if err != nil {
		t.Fatal(err)
	}
	vec.AAD, vec.Payload = hex.EncodeToString(a), hex.EncodeToString(s)
	out, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if *writeVectors {
		if werr := os.WriteFile(sealVectorsPath, out, 0o600); werr != nil {
			t.Fatal(werr)
		}
		return
	}
	want, err := os.ReadFile(sealVectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -write-vectors once, and review the result)", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("sealing differs from %s", sealVectorsPath)
	}
}
