package tally

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Golden records, assembled by hand from SPEC §2 field by field. They are not
// produced by this package's encoder, so an encoder and decoder that agree on
// the same wrong layout still fail here. The leaf hashes were computed with
//
//	printf '00<record hex>' | xxd -r -p | shasum -a 256
//
// independently of the implementation (#12, "done when").
const (
	goldenGenesisHex = "01" + "01" + // version, type GENESIS
		"000102030405060708090a0b0c0d0e0f" + // log_id
		"0000000000000000" + // seq = 0
		"0102030405060708" + // created_at
		"0000000f" + "6578616d706c652e636f6d2f6c6f67" // origin "example.com/log"
	goldenGenesisLeaf = "90453ef98d93b3ed97096aee5e6363dadbffb8d8c8899e44686e2ce5a9c6830f"

	goldenEntryHex = "01" + "02" + // version, type ENTRY
		"000102030405060708090a0b0c0d0e0f" + // log_id
		"0000000000000001" + // seq
		"0102030405060709" + // recorded_at
		"0102030405060700" + // occurred_at
		"00000002" + "6531" + // event_id "e1"
		"03" + // actor_kind system
		"00000000" + // actor_id empty
		"0000000a" + "757365722e6c6f67696e" + // action "user.login"
		"00000000" + // resource empty
		"01" + // outcome success
		"00" + // payload_kind none
		"00000000" + // subject_ref empty
		"00000000" + // payload empty
		goldenGenesisLeaf // prev_hash: genesis's leaf hash
	goldenEntryLeaf = "5b9a49f0f485bab009a213f35ca28dce6c7ba03613165c677e1da71dd6ba970c"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test: %v", err)
	}
	return b
}

var testLogID = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

func goldenGenesis() *genesis {
	return &genesis{logID: testLogID, createdAt: 0x0102030405060708, origin: "example.com/log"}
}

func goldenEntry(t *testing.T) *entry {
	var prev [32]byte
	copy(prev[:], unhex(t, goldenGenesisLeaf))
	return &entry{
		logID:       testLogID,
		seq:         1,
		recordedAt:  0x0102030405060709,
		occurredAt:  0x0102030405060700,
		eventID:     []byte("e1"),
		actorKind:   actorSystem,
		actorID:     []byte{},
		action:      "user.login",
		resource:    "",
		outcome:     outcomeSuccess,
		payloadKind: payloadNone,
		subjectRef:  []byte{},
		payload:     []byte{},
		prevHash:    prev,
	}
}

// Negative control: dropping the 0x00 prefix in leafHash made both cases fail.
func TestLeafHashMatchesIndependentVector(t *testing.T) {
	for _, tc := range []struct{ name, body, leaf string }{
		{"genesis", goldenGenesisHex, goldenGenesisLeaf},
		{"entry", goldenEntryHex, goldenEntryLeaf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := leafHash(unhex(t, tc.body))
			if hex.EncodeToString(got[:]) != tc.leaf {
				t.Fatalf("leafHash = %x, want %s", got, tc.leaf)
			}
		})
	}
}

func TestEncodeMatchesGoldenLayout(t *testing.T) {
	g, err := encodeRecord(goldenGenesis())
	if err != nil {
		t.Fatalf("encode genesis: %v", err)
	}
	if want := unhex(t, goldenGenesisHex); !bytes.Equal(g, want) {
		t.Errorf("genesis\n got %x\nwant %x", g, want)
	}
	e, err := encodeRecord(goldenEntry(t))
	if err != nil {
		t.Fatalf("encode entry: %v", err)
	}
	if want := unhex(t, goldenEntryHex); !bytes.Equal(e, want) {
		t.Errorf("entry\n got %x\nwant %x", e, want)
	}
}

func TestDecodeGolden(t *testing.T) {
	r, err := decodeRecord(unhex(t, goldenGenesisHex))
	if err != nil {
		t.Fatalf("decode genesis: %v", err)
	}
	g, ok := r.(*genesis)
	if !ok || *g != *goldenGenesis() {
		t.Errorf("genesis = %#v", r)
	}

	r, err = decodeRecord(unhex(t, goldenEntryHex))
	if err != nil {
		t.Fatalf("decode entry: %v", err)
	}
	e, ok := r.(*entry)
	if !ok {
		t.Fatalf("entry decoded as %T", r)
	}
	want := goldenEntry(t)
	if e.seq != want.seq || e.action != want.action || e.prevHash != want.prevHash ||
		!bytes.Equal(e.eventID, want.eventID) || e.actorKind != want.actorKind {
		t.Errorf("entry = %#v", e)
	}
}

func TestRoundTripVariants(t *testing.T) {
	ref := bytes.Repeat([]byte{0xAA}, 16)
	sealed := append([]byte{sealFormatV1}, bytes.Repeat([]byte{0x55}, 28)...)
	for name, mutate := range map[string]func(e *entry){
		"subject actor":  func(e *entry) { e.actorKind, e.actorID = actorSubject, ref },
		"service actor":  func(e *entry) { e.actorKind, e.actorID = actorService, []byte("billing-api") },
		"plain payload":  func(e *entry) { e.payloadKind, e.payload = payloadPlain, []byte{0} },
		"sealed payload": func(e *entry) { e.payloadKind, e.subjectRef, e.payload = payloadSealed, ref, sealed },
		"resource":       func(e *entry) { e.resource = "invoice/2026/ação" },
		"denied":         func(e *entry) { e.outcome = outcomeDenied },
	} {
		t.Run(name, func(t *testing.T) {
			e := goldenEntry(t)
			mutate(e)
			b, err := encodeRecord(e)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if _, err := decodeRecord(b); err != nil {
				t.Fatalf("decode: %v", err)
			}
		})
	}
}

// Each case changes the golden bytes so that exactly one rule is broken, and
// expects errMalformed. A loop over offsets would find something wrong for
// almost any change; these name the rule.
//
// Negative controls, each seen failing with its check removed: version, type,
// each enum, genesis seq, trailing bytes, and the shape rules by kind.
func TestDecodeRejectsMalformed(t *testing.T) {
	// Offsets into goldenEntryHex, in bytes.
	const (
		offVersion   = 0
		offType      = 1
		offActorKind = 2 + 16 + 8 + 8 + 8 + 4 + 2
		offOutcome   = offActorKind + 1 + 4 + 4 + 10 + 4
		offPayload   = offOutcome + 1
	)
	entryWith := func(off int, v byte) func(t *testing.T) []byte {
		return func(t *testing.T) []byte {
			b := unhex(t, goldenEntryHex)
			b[off] = v
			return b
		}
	}
	cases := map[string]func(t *testing.T) []byte{
		"version 0":         entryWith(offVersion, 0),
		"version 2":         entryWith(offVersion, 2),
		"type 0":            entryWith(offType, 0),
		"type 3":            entryWith(offType, 3),
		"actor_kind 0":      entryWith(offActorKind, 0),
		"actor_kind 4":      entryWith(offActorKind, 4),
		"outcome 0":         entryWith(offOutcome, 0),
		"outcome 5":         entryWith(offOutcome, 5),
		"payload_kind 3":    entryWith(offPayload, 3),
		"trailing byte":     func(t *testing.T) []byte { return append(unhex(t, goldenEntryHex), 0) },
		"empty":             func(*testing.T) []byte { return nil },
		"genesis seq 1":     func(t *testing.T) []byte { b := unhex(t, goldenGenesisHex); b[2+16+7] = 1; return b },
		"genesis truncated": func(t *testing.T) []byte { b := unhex(t, goldenGenesisHex); return b[:len(b)-1] },
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRecord(body(t)); !errors.Is(err, errMalformed) {
				t.Fatalf("decode = %v, want errMalformed", err)
			}
		})
	}
}

// The validity rules of SPEC §2 that need no chain context. Each case breaks
// one; both directions are checked, because a writer that could encode the
// record would commit one no verifier accepts.
func TestValidityRules(t *testing.T) {
	ref := bytes.Repeat([]byte{0xAA}, 16)
	sealedOK := append([]byte{sealFormatV1}, make([]byte, 28)...)
	cases := map[string]func(e *entry){
		"event_id empty":           func(e *entry) { e.eventID = []byte{} },
		"subject actor 15 bytes":   func(e *entry) { e.actorKind, e.actorID = actorSubject, ref[:15] },
		"service actor empty":      func(e *entry) { e.actorKind, e.actorID = actorService, []byte{} },
		"service actor with @":     func(e *entry) { e.actorKind, e.actorID = actorService, []byte("joao@example.com") },
		"service actor with space": func(e *entry) { e.actorKind, e.actorID = actorService, []byte("billing api") },
		"service actor not UTF-8":  func(e *entry) { e.actorKind, e.actorID = actorService, []byte{0xFF} },
		"system actor not empty":   func(e *entry) { e.actorID = []byte("x") },
		"action one segment":       func(e *entry) { e.action = "login" },
		"action uppercase":         func(e *entry) { e.action = "user.Login" },
		"action leading digit":     func(e *entry) { e.action = "user.1login" },
		"action empty segment":     func(e *entry) { e.action = "user..login" },
		"action trailing dot":      func(e *entry) { e.action = "user.login." },
		"resource with @":          func(e *entry) { e.resource = "a@b" },
		"resource with NBSP":       func(e *entry) { e.resource = "a\u00a0b" },
		"resource with RLO":        func(e *entry) { e.resource = "a\u202eb" },
		"resource with ZWSP":       func(e *entry) { e.resource = "a\u200bb" },
		"resource with NEL":        func(e *entry) { e.resource = "a\u0085b" },
		"none with payload":        func(e *entry) { e.payload = []byte{1} },
		"none with subject_ref":    func(e *entry) { e.subjectRef = ref },
		"plain empty":              func(e *entry) { e.payloadKind = payloadPlain },
		"plain with subject_ref":   func(e *entry) { e.payloadKind, e.payload, e.subjectRef = payloadPlain, []byte{1}, ref },
		"sealed without ref":       func(e *entry) { e.payloadKind, e.payload = payloadSealed, sealedOK },
		"sealed 28 bytes":          func(e *entry) { e.payloadKind, e.subjectRef, e.payload = payloadSealed, ref, sealedOK[:28] },
		"sealed format 0x02": func(e *entry) {
			p := bytes.Clone(sealedOK)
			p[0] = 0x02
			e.payloadKind, e.subjectRef, e.payload = payloadSealed, ref, p
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := goldenEntry(t)
			mutate(e)
			if _, err := encodeRecord(e); !errors.Is(err, errMalformed) {
				t.Errorf("encode = %v, want errMalformed", err)
			}
			// Bypass the encoder's own check to hand the decoder the bytes.
			b, err := encodeFields(e)
			if err != nil {
				t.Fatalf("raw encode: %v", err)
			}
			if _, err := decodeRecord(b); !errors.Is(err, errMalformed) {
				t.Errorf("decode = %v, want errMalformed", err)
			}
		})
	}
}

// Negative controls: removing the empty, "+" and cleanText checks in
// validateGenesis each made its case fail.
func TestOriginRules(t *testing.T) {
	for name, origin := range map[string]string{
		"empty":     "",
		"plus":      "a+b",
		"space":     "a b",
		"tab":       "a\tb",
		"ideograph": "a\u3000b",
		"bidi":      "a\u2066b",
		"control":   "a\x01b",
		"DEL":       "a\x7fb",
		"over 256":  strings.Repeat("a", 257),
	} {
		t.Run(name, func(t *testing.T) {
			g := goldenGenesis()
			g.origin = origin
			if _, err := encodeRecord(g); !errors.Is(err, errMalformed) {
				t.Errorf("encode = %v, want errMalformed", err)
			}
		})
	}
	g := goldenGenesis()
	g.origin = strings.Repeat("a", 256)
	if _, err := encodeRecord(g); err != nil {
		t.Errorf("origin at the 256-byte ceiling: %v", err)
	}
}

// Every code point SPEC §1.1 lists is forbidden, and its neighbours are not.
// The table is checked against the spec's ranges, not against itself.
func TestForbiddenCodePoints(t *testing.T) {
	ranges := [][2]rune{
		{0x0000, 0x001F}, {0x007F, 0x009F},
		{0x0020, 0x0020}, {0x0085, 0x0085}, {0x00A0, 0x00A0}, {0x1680, 0x1680},
		{0x2000, 0x200A}, {0x2028, 0x2029}, {0x202F, 0x202F}, {0x205F, 0x205F}, {0x3000, 0x3000},
		{0x180E, 0x180E}, {0x200B, 0x200F}, {0x202A, 0x202E}, {0x2060, 0x2064}, {0x2066, 0x206F},
		{0xFEFF, 0xFEFF},
	}
	in := func(r rune) bool {
		for _, rg := range ranges {
			if r >= rg[0] && r <= rg[1] {
				return true
			}
		}
		return false
	}
	checked := 0
	for r := rune(0); r <= 0x10000; r++ {
		if got, want := forbidden(r), in(r); got != want {
			t.Errorf("forbidden(%U) = %v, want %v", r, got, want)
		}
		checked++
	}
	if checked != 0x10001 {
		t.Fatalf("checked %d code points", checked)
	}
}

// SPEC §1 rule 4. A correct strict decoder of a fixed-width encoding always
// re-encodes identically, so the check can only be exercised with an encoder
// that disagrees with the decoder: the defect it exists to catch.
//
// Negative control: removing the bytes.Equal comparison in decodeRecordWith
// made this fail.
func TestReencodeMustBeByteIdentical(t *testing.T) {
	body := unhex(t, goldenEntryHex)
	skewed := func(r record) ([]byte, error) {
		b, err := encodeRecord(r)
		if err != nil {
			return nil, err
		}
		b[len(b)-1] ^= 1
		return b, nil
	}
	if _, err := decodeRecordWith(body, skewed); !errors.Is(err, errNonCanonical) {
		t.Fatalf("decode = %v, want errNonCanonical", err)
	}
	if _, err := decodeRecordWith(body, encodeRecord); err != nil {
		t.Fatalf("decode with the real encoder: %v", err)
	}
}

// Decoding copies: a record must not alias the frame buffer, which a reader
// reuses for the next frame.
func TestDecodedRecordDoesNotAliasBody(t *testing.T) {
	body := unhex(t, goldenEntryHex)
	r, err := decodeRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	for i := range body {
		body[i] = 0xEE
	}
	if e := r.(*entry); string(e.eventID) != "e1" || e.action != "user.login" {
		t.Fatalf("decoded entry changed with its input: %#v", e)
	}
}
