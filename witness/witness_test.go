package witness

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/merkle"
	"github.com/JonasBorgesLM/tally/internal/note"
	"github.com/JonasBorgesLM/tally/tallytest"
)

// fixture is a witness serving one log, over HTTP, and that log's keys.
type fixture struct {
	t       *testing.T
	dir     string
	srv     *httptest.Server
	logKey  string // the log's verifier key
	witSkey string
	witVkey string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	wsk, wvk, err := note.GenerateCosignerKey(bytes.NewReader(bytes.Repeat([]byte{7}, 32)), "witness.example")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, dir: dir, logKey: tallytest.TestVerifierKey, witSkey: wsk, witVkey: wvk}
	f.start()
	return f
}

// start serves a witness over f.dir, a fresh one each time, as a restart is.
func (f *fixture) start() {
	f.t.Helper()
	w, err := New(f.dir, f.witSkey, []string{f.logKey})
	if err != nil {
		f.t.Fatal(err)
	}
	if f.srv != nil {
		f.srv.Close()
	}
	f.srv = httptest.NewServer(w)
	f.t.Cleanup(f.srv.Close)
}

// post sends one add-checkpoint and returns the status and the body.
func (f *fixture) post(old uint64, proof [][32]byte, cp tally.SignedCheckpoint) (status int, body string) {
	f.t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "old %d\n", old)
	for _, h := range proof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}
	b.WriteString("\n")
	b.Write(cp)
	return f.raw(b.String())
}

func (f *fixture) raw(body string) (status int, out string) {
	f.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.srv.URL+"/add-checkpoint", strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(resp.Body); err != nil {
		f.t.Fatal(err)
	}
	return resp.StatusCode, buf.String()
}

// history is a tally log written with the published test key, whose ids
// after the first `shared` entries carry prefix, so two histories share a
// genesis and diverge there: the host's fork, signed with the log's key.
type history struct {
	leaves [][32]byte
	tlogs  map[uint64]tally.SignedCheckpoint
}

func newHistory(t *testing.T, prefix string, n, shared int, cpAt ...int) history {
	t.Helper()
	ctx := context.Background()
	signer, err := note.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	mem := tallytest.NewMemStore()
	clock := tallytest.NewFixedClock(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	l, err := tally.Open(ctx, keepOpen{mem}, signer, tally.WithCheckpointEvery(0, 0),
		tally.WithRand(bytes.NewReader(bytes.Repeat([]byte{3}, 16))), tally.WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		id := fmt.Sprintf("a%d", i)
		if i >= shared {
			id = fmt.Sprintf("%s%d", prefix, i)
		}
		clock.Advance(time.Second)
		ev := tally.Event{ID: tally.EventID(id), OccurredAt: time.Unix(1_800_000_000, 0), Actor: tally.System(),
			Action: "user.login", Outcome: tally.OutcomeSuccess}
		if _, err = l.Append(ctx, ev); err != nil {
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
	h := history{tlogs: map[uint64]tally.SignedCheckpoint{}}
	for r, err := range mem.Records(ctx, 0) {
		if err != nil {
			t.Fatal(err)
		}
		h.leaves = append(h.leaves, tally.LeafHash(r.Body))
	}
	for cp, err := range mem.Checkpoints(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		text, _, _ := strings.Cut(string(cp), "\n\n")
		if lines := strings.Split(text, "\n"); len(lines) == 3 {
			size, _ := strconv.ParseUint(lines[1], 10, 64)
			h.tlogs[size] = cp
		}
	}
	return h
}

// keepOpen hides Close, so the history can be read after the log closes.
type keepOpen struct{ tally.Store }

func (keepOpen) Close() error { return nil }

func (h history) proof(t *testing.T, m, n uint64) [][32]byte {
	t.Helper()
	tree, err := merkle.NewTree(0, nil, h.leaves[:n])
	if err != nil {
		t.Fatal(err)
	}
	p, err := tree.ConsistencyProof(m, n)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// cosignedBy reports whether line is the witness's valid cosignature of cp.
func (f *fixture) cosignedBy(cp tally.SignedCheckpoint, line string) bool {
	f.t.Helper()
	lv, err := note.NewVerifier(f.logKey)
	if err != nil {
		f.t.Fatal(err)
	}
	wv, err := note.NewVerifier(f.witVkey)
	if err != nil {
		f.t.Fatal(err)
	}
	n, err := note.Open(append(bytes.Clone(cp), line...), []*note.Verifier{lv, wv})
	return err == nil && len(n.Cosignatures) == 1
}

// The protocol, step by step: a first checkpoint from size 0, a 409 that
// names the witness's size, a consistent one, the same size again, and the
// state surviving a restart.
func TestAddCheckpoint(t *testing.T) {
	f := newFixture(t)
	h := newHistory(t, "a", 9, 9, 3, 6) // tlog-checkpoints of 4, 7 and 10

	status, body := f.post(0, nil, h.tlogs[4])
	if status != http.StatusOK || !f.cosignedBy(h.tlogs[4], body) {
		t.Fatalf("first: %d %q", status, body)
	}
	if status, body = f.post(0, nil, h.tlogs[7]); status != http.StatusConflict || body != "4\n" {
		t.Fatalf("a stale old size: %d %q, want 409 naming 4", status, body)
	}
	if status, body = f.post(4, h.proof(t, 4, 7), h.tlogs[7]); status != http.StatusOK || !f.cosignedBy(h.tlogs[7], body) {
		t.Fatalf("consistent: %d %q", status, body)
	}
	if status, body = f.post(7, nil, h.tlogs[7]); status != http.StatusOK || !f.cosignedBy(h.tlogs[7], body) {
		t.Fatalf("the same size again: %d %q", status, body)
	}
	f.start()
	if status, body = f.post(0, nil, h.tlogs[10]); status != http.StatusConflict || body != "7\n" {
		t.Fatalf("after a restart: %d %q, want 409 naming 7", status, body)
	}
}

// T-09: the host's fork, from the same genesis and signed with the log's key,
// is refused once the witness has cosigned the honest history, at a larger
// size and at the same size, and the witness's state does not move.
//
// Negative control: with the consistency check removed, the fork at 10 was
// cosigned. Verified by hand, restored before committing.
func TestAForkIsNotCosigned(t *testing.T) {
	f := newFixture(t)
	honest := newHistory(t, "a", 9, 9, 3, 6)
	fork := newHistory(t, "b", 9, 5, 3, 6) // diverges after entry 5, so at leaf 6

	if status, _ := f.post(0, nil, honest.tlogs[4]); status != http.StatusOK {
		t.Fatal(status)
	}
	if status, _ := f.post(4, honest.proof(t, 4, 7), honest.tlogs[7]); status != http.StatusOK {
		t.Fatal(status)
	}
	if status, body := f.post(7, fork.proof(t, 7, 10), fork.tlogs[10]); status != http.StatusUnprocessableEntity {
		t.Fatalf("the fork at 10: %d %q, want 422", status, body)
	}
	if status, body := f.post(7, nil, fork.tlogs[7]); status != http.StatusUnprocessableEntity {
		t.Fatalf("the fork at 7, the witnessed size: %d %q, want 422", status, body)
	}
	if status, body := f.post(0, nil, honest.tlogs[10]); status != http.StatusConflict || body != "7\n" {
		t.Fatalf("after the refusals: %d %q, want the state still at 7", status, body)
	}
}

// Every refusal the protocol names, each with its status.
func TestAddCheckpointRefusals(t *testing.T) {
	f := newFixture(t)
	h := newHistory(t, "a", 6, 6, 3)
	other, _, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 32)), "example.com/log")
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := note.NewSigner(other)
	if err != nil {
		t.Fatal(err)
	}
	text, _, _ := strings.Cut(string(h.tlogs[4]), "\n\n")
	forged, err := note.Sign([]byte(text+"\n"), otherSigner)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := note.Sign([]byte("other.example/log\n4\n"+strings.Split(text, "\n")[2]+"\n"), otherSigner)
	if err != nil {
		t.Fatal(err)
	}
	withExt, err := note.Sign([]byte(text+"\nextension\n"), mustSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"signed by another key", http.StatusForbidden, "old 0\n\n" + string(forged)},
		{"an unknown origin", http.StatusNotFound, "old 0\n\n" + string(unknown)},
		{"old above the size", http.StatusBadRequest, "old 9\n\n" + string(h.tlogs[4])},
		{"a proof from 0", http.StatusUnprocessableEntity, "old 0\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n" + string(h.tlogs[4])},
		{"an extension line", http.StatusBadRequest, "old 0\n\n" + string(withExt)},
		{"no old line", http.StatusBadRequest, "\n" + string(h.tlogs[4])},
		{"a leading zero", http.StatusBadRequest, "old 00\n\n" + string(h.tlogs[4])},
		{"64 proof lines", http.StatusBadRequest, "old 1\n" + strings.Repeat("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", 64) + "\n" + string(h.tlogs[4])},
		{"not a note", http.StatusBadRequest, "old 0\n\nexample.com/log\n4\n"},
	}
	for _, c := range cases {
		if status, body := f.raw(c.body); status != c.status {
			t.Errorf("%s: %d %q, want %d", c.name, status, body, c.status)
		}
	}
	if len(cases) != 9 {
		t.Fatalf("ran %d cases, want 9", len(cases))
	}
	if status, _ := f.post(0, nil, h.tlogs[4]); status != http.StatusOK {
		t.Fatalf("after the refusals, a valid first checkpoint: %d", status)
	}
}

func mustSigner(t *testing.T) *note.Signer {
	t.Helper()
	s, err := note.NewSigner(tallytest.TestSignerKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The state is durable before the answer: when it cannot be written, the
// witness answers an error and no cosignature.
//
// Negative control: with the write's error ignored, the witness returned a
// cosignature it had not stored. Verified by hand, restored before committing.
func TestNoCosignatureWithoutTheState(t *testing.T) {
	f := newFixture(t)
	h := newHistory(t, "a", 3, 3)
	if err := os.Chmod(f.dir, 0o500); err != nil { // #nosec G302 -- a test's own directory, made unwritable on purpose
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.dir, 0o700) }) // #nosec G302 -- restoring the directory's own mode
	status, body := f.post(0, nil, h.tlogs[4])
	if status != http.StatusInternalServerError || strings.Contains(body, "—") {
		t.Fatalf("an unwritable state: %d %q, want 500 and no cosignature", status, body)
	}
}

// Two hosts racing from the same size: one is cosigned, the other learns the
// new size. The check and the write are one step.
func TestConcurrentAddsDoNotRollBack(t *testing.T) {
	f := newFixture(t)
	h := newHistory(t, "a", 9, 9, 3, 6)
	if status, _ := f.post(0, nil, h.tlogs[4]); status != http.StatusOK {
		t.Fatal(status)
	}
	var wg sync.WaitGroup
	statuses := make([]int, 2)
	for i, n := range []uint64{7, 10} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], _ = f.post(4, h.proof(t, 4, n), h.tlogs[n])
		}()
	}
	wg.Wait()
	ok, conflict := 0, 0
	for _, s := range statuses {
		switch s {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("statuses %v, want one 200 and one 409", statuses)
	}
}

// A state directory others can reach is refused: whoever writes it rolls the
// witness back.
func TestLoosePermissionsAreRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil { // #nosec G302 -- the loose mode under test
		t.Fatal(err)
	}
	wsk, _, err := note.GenerateCosignerKey(bytes.NewReader(bytes.Repeat([]byte{7}, 32)), "witness.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, wsk, []string{tallytest.TestVerifierKey}); err == nil {
		t.Fatal("a 0750 state directory was accepted")
	}
}
