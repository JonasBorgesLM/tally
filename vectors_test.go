package tally

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

// The published test vectors (SPEC §8), for an independent implementation to
// check itself against. They are written once, by hand-run generation, and
// committed: the suite only compares. A suite that regenerated them would
// update them silently on a format break, which is the one change they exist
// to catch.
//
//	go test -run TestRecordVectors -write-vectors .   # then review the diff
var writeVectors = flag.Bool("write-vectors", false, "regenerate testdata/vectors (review the diff before committing)")

// A constant, not a computed path: the vectors are always these files.
const recordVectorsPath = "testdata/vectors/records.json"

type vectorFile struct {
	Comment string         `json:"comment"`
	Records []recordVector `json:"records"`
}

// recordVector holds a record three ways: its fields, readable; the exact
// stored bytes; and the leaf hash of those bytes. 64-bit integers are decimal
// strings, so that a JSON reader using float64 does not round them.
type recordVector struct {
	Name     string         `json:"name"`
	Genesis  *genesisFields `json:"genesis,omitempty"`
	Entry    *entryFields   `json:"entry,omitempty"`
	BodyHex  string         `json:"body_hex"`
	LeafHash string         `json:"leaf_hash_hex"`
}

type genesisFields struct {
	LogID     string `json:"log_id_hex"`
	CreatedAt int64  `json:"created_at,string"`
	Origin    string `json:"origin"`
}

type entryFields struct {
	LogID       string `json:"log_id_hex"`
	Seq         uint64 `json:"seq,string"`
	RecordedAt  int64  `json:"recorded_at,string"`
	OccurredAt  int64  `json:"occurred_at,string"`
	EventID     string `json:"event_id_hex"`
	ActorKind   uint8  `json:"actor_kind"`
	ActorID     string `json:"actor_id_hex"`
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	Outcome     uint8  `json:"outcome"`
	PayloadKind uint8  `json:"payload_kind"`
	SubjectRef  string `json:"subject_ref_hex"`
	Payload     string `json:"payload_hex"`
	PrevHash    string `json:"prev_hash_hex"`
}

// vectorLog is the log the vectors describe: genesis and four entries, chained,
// together covering every actor_kind, payload_kind and outcome. Genesis is the
// hand-assembled golden record of record_test.go, whose leaf hash was computed
// with shasum, so the published chain is anchored to a value this package did
// not compute.
func vectorLog(t *testing.T) []record {
	t.Helper()
	ref := SubjectRef{0x5e, 0x1f, 0x0a, 0x9c, 0x33, 0x71, 0x42, 0x0d, 0xe8, 0x15, 0x6b, 0x27, 0x90, 0xc4, 0x08, 0xb1}
	sealed := append([]byte{sealFormatV1},
		unhex(t, "000102030405060708090a0b"+ // nonce
			"5d41402abc4b2a76b9719d911017c592"+ // ciphertext (opaque to a verifier)
			"7f2c1a0e9d8b6a5c4e3f2d1c0b0a0908")...) // GCM tag
	b := newLog(t)
	b.entry(nil) // system actor, no payload, success
	b.entry(func(e *entry) {
		e.eventID = []byte("01J9Z3K8V7QW")
		e.actorKind, e.actorID = actorSubject, ref[:]
		e.action, e.resource = "account.password.change", "account/7f3a"
		e.outcome = OutcomeDenied
		e.payloadKind, e.subjectRef, e.payload = payloadSealed, ref[:], sealed
	})
	b.entry(func(e *entry) {
		e.eventID = []byte{0x8a, 0x00, 0xff, 0x10}
		e.actorKind, e.actorID = actorService, []byte("billing-api")
		e.action, e.resource = "invoice.issue", "fatura/2026/ação-nº7"
		e.outcome = OutcomeFailure
		e.payloadKind, e.payload = payloadPlain, []byte(`{"amount_cents":12345,"reason":"card_declined"}`)
	})
	b.entry(func(e *entry) {
		e.eventID = []byte("e4")
		e.actorKind, e.actorID = actorService, []byte("scheduler")
		e.action = "retention.prune_check"
		e.outcome = OutcomeError
		e.occurredAt = -1 // before the epoch: occurred_at is untrusted and any int64 is valid
	})

	var recs []record
	for rest := b.buf; len(rest) > 0; {
		body, next, err := readFrame(rest)
		if err != nil {
			t.Fatal(err)
		}
		r, err := decodeRecord(body)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
		rest = next
	}
	return recs
}

func toVector(t *testing.T, name string, r record) recordVector {
	t.Helper()
	body, err := encodeRecord(r)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	leaf := leafHash(body)
	v := recordVector{Name: name, BodyHex: hex.EncodeToString(body), LeafHash: hex.EncodeToString(leaf[:])}
	switch r := r.(type) {
	case *genesis:
		v.Genesis = &genesisFields{LogID: hex.EncodeToString(r.logID[:]), CreatedAt: r.createdAt, Origin: r.origin}
	case *entry:
		v.Entry = &entryFields{
			LogID: hex.EncodeToString(r.logID[:]), Seq: r.seq, RecordedAt: r.recordedAt, OccurredAt: r.occurredAt,
			EventID: hex.EncodeToString(r.eventID), ActorKind: uint8(r.actorKind), ActorID: hex.EncodeToString(r.actorID),
			Action: r.action, Resource: r.resource, Outcome: uint8(r.outcome), PayloadKind: uint8(r.payloadKind),
			SubjectRef: hex.EncodeToString(r.subjectRef), Payload: hex.EncodeToString(r.payload),
			PrevHash: hex.EncodeToString(r.prevHash[:]),
		}
	}
	return v
}

// fromVector builds a record from the readable fields alone, the way an
// independent implementation would, without looking at body_hex.
func fromVector(t *testing.T, v recordVector) record {
	t.Helper()
	fixed := func(dst []byte, s string) {
		if b := unhex(t, s); copy(dst, b) != len(dst) || len(b) != len(dst) {
			t.Fatalf("%s: %q is not %d bytes", v.Name, s, len(dst))
		}
	}
	switch {
	case v.Genesis != nil && v.Entry == nil:
		g := &genesis{createdAt: v.Genesis.CreatedAt, origin: v.Genesis.Origin}
		fixed(g.logID[:], v.Genesis.LogID)
		return g
	case v.Entry != nil && v.Genesis == nil:
		f := v.Entry
		e := &entry{
			seq: f.Seq, recordedAt: f.RecordedAt, occurredAt: f.OccurredAt,
			eventID: unhex(t, f.EventID), actorKind: actorKind(f.ActorKind), actorID: unhex(t, f.ActorID),
			action: f.Action, resource: f.Resource, outcome: Outcome(f.Outcome), payloadKind: payloadKind(f.PayloadKind),
			subjectRef: unhex(t, f.SubjectRef), payload: unhex(t, f.Payload),
		}
		fixed(e.logID[:], f.LogID)
		fixed(e.prevHash[:], f.PrevHash)
		return e
	}
	t.Fatalf("%s: exactly one of genesis and entry must be set", v.Name)
	return nil
}

// The committed vectors are what the encoder produces, byte for byte, and what
// the decoder reads back. A format change fails here until SPEC.md and the
// vectors are updated together (CLAUDE.md, Conventions).
//
// Negative control: swapping outcome and payload_kind in both the encoder and
// the decoder, a consistent format change, made this fail with "encoder output
// differs from the committed bytes", while TestDecodeAfterEncodeIsIdentity
// still passed. That is the change vectors exist to catch: a round trip cannot
// see it.
func TestRecordVectors(t *testing.T) {
	names := []string{"genesis", "entry-system-none-success", "entry-subject-sealed-denied",
		"entry-service-plain-failure", "entry-service-none-error"}
	recs := vectorLog(t)
	if len(recs) != len(names) {
		t.Fatalf("vectorLog has %d records, want %d", len(recs), len(names))
	}

	if *writeVectors {
		f := vectorFile{
			Comment: "tally SPEC v1 record vectors. See README.md in this directory. Do not edit by hand.",
		}
		for i, r := range recs {
			f.Records = append(f.Records, toVector(t, names[i], r))
		}
		out, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(recordVectorsPath, append(out, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s: review the diff before committing", recordVectorsPath)
	}

	raw, err := os.ReadFile(recordVectorsPath)
	if err != nil {
		t.Fatalf("reading the committed vectors: %v", err)
	}
	var f vectorFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("parsing %s: %v", recordVectorsPath, err)
	}
	if len(f.Records) != len(names) {
		t.Fatalf("%d committed vectors, want %d", len(f.Records), len(names))
	}

	var log []byte
	for i, v := range f.Records {
		t.Run(v.Name, func(t *testing.T) {
			if v.Name != names[i] {
				t.Fatalf("vector %d is %q, want %q", i, v.Name, names[i])
			}
			body := unhex(t, v.BodyHex)

			// The fields alone encode to the committed bytes.
			got, err := encodeRecord(fromVector(t, v))
			if err != nil {
				t.Fatalf("encoding the fields: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Fatalf("encoder output differs from the committed bytes\n got %x\nwant %x", got, body)
			}
			// The bytes decode to the fields.
			r, err := decodeRecord(body)
			if err != nil {
				t.Fatalf("decoding the committed bytes: %v", err)
			}
			if back := toVector(t, v.Name, r); back != v && !sameVector(back, v) {
				t.Fatalf("decoded fields differ from the committed ones")
			}
			// The leaf hash is of the committed bytes.
			if leaf := leafHash(body); hex.EncodeToString(leaf[:]) != v.LeafHash {
				t.Fatalf("leaf hash %x, committed %s", leaf, v.LeafHash)
			}
			// And the generator still produces this record.
			want, err := encodeRecord(recs[i])
			if err != nil || !bytes.Equal(want, body) {
				t.Fatalf("vectorLog's record %d differs from the committed bytes (%v)", i, err)
			}
		})
		log = appendFrame(log, unhex(t, v.BodyHex))
	}

	// Anchored to the independently computed golden genesis.
	if f.Records[0].BodyHex != goldenGenesisHex || f.Records[0].LeafHash != goldenGenesisLeaf {
		t.Fatal("the genesis vector is not the shasum-checked golden genesis")
	}
	// The vectors form one valid chain, covered by a head on its last leaf.
	last := f.Records[len(f.Records)-1]
	head := &trustedHead{size: uint64(len(f.Records))}
	copy(head.hash[:], unhex(t, last.LeafHash))
	if size, v := verifyFrames(log, head); v != nil || size != uint64(len(f.Records)) {
		t.Fatalf("the vectors do not form a valid chain: size %d, %v", size, v)
	}
}

// sameVector compares two vectors field by field; recordVector holds pointers,
// so == compares addresses.
func sameVector(a, b recordVector) bool {
	if a.Name != b.Name || a.BodyHex != b.BodyHex || a.LeafHash != b.LeafHash {
		return false
	}
	switch {
	case a.Genesis != nil && b.Genesis != nil:
		return *a.Genesis == *b.Genesis && a.Entry == nil && b.Entry == nil
	case a.Entry != nil && b.Entry != nil:
		return *a.Entry == *b.Entry && a.Genesis == nil && b.Genesis == nil
	}
	return false
}

// Every actor_kind, payload_kind and outcome appears in the committed vectors
// (#15, "done when").
func TestVectorsCoverEveryKind(t *testing.T) {
	raw, err := os.ReadFile(recordVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	actors, payloads, outcomes, genesisCount := map[uint8]bool{}, map[uint8]bool{}, map[uint8]bool{}, 0
	for _, v := range f.Records {
		if v.Genesis != nil {
			genesisCount++
			continue
		}
		actors[v.Entry.ActorKind] = true
		payloads[v.Entry.PayloadKind] = true
		outcomes[v.Entry.Outcome] = true
	}
	if genesisCount != 1 || len(actors) != 3 || len(payloads) != 3 || len(outcomes) != 4 {
		t.Fatalf("coverage: %d genesis, actor kinds %v, payload kinds %v, outcomes %v",
			genesisCount, actors, payloads, outcomes)
	}
}
