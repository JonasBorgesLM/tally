package seal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/tally"
	"github.com/JonasBorgesLM/tally/internal/fsx"
)

func kek(t *testing.T, id string, fill byte) KEK {
	t.Helper()
	k, err := NewLocalKEK(id, bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func vaultDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "vault")
}

func open(t *testing.T, dir string, k KEK, opts ...Option) *FileVault {
	t.Helper()
	v, err := OpenFileVault(context.Background(), dir, k, opts...)
	if err != nil {
		t.Fatalf("OpenFileVault: %v", err)
	}
	return v
}

func resolve(t *testing.T, v *FileVault, id string) tally.SubjectRef {
	t.Helper()
	ref, err := v.Resolve(context.Background(), []byte(id))
	if err != nil {
		t.Fatalf("Resolve(%q): %v", id, err)
	}
	return ref
}

func dekOf(t *testing.T, v *FileVault, ref tally.SubjectRef) []byte {
	t.Helper()
	k, err := v.dek(context.Background(), ref)
	if err != nil {
		t.Fatalf("dek: %v", err)
	}
	return k
}

// seq is a deterministic random source: 0x00, 0x01, 0x02, ...
type seq struct{ n byte }

func (s *seq) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = s.n
		s.n++
	}
	return len(p), nil
}

// A ref is stable for an identifier, across a reopen, and distinct between
// identifiers; the identifier is stored nowhere in the vault (RF-11).
func TestResolve(t *testing.T) {
	dir := vaultDir(t)
	a := kek(t, "a", 1)
	v := open(t, dir, a)
	alice := resolve(t, v, "alice@example.com")
	if again := resolve(t, v, "alice@example.com"); again != alice {
		t.Fatal("a second Resolve returned another ref")
	}
	if bob := resolve(t, v, "bob@example.com"); bob == alice {
		t.Fatal("two identifiers share a ref")
	}
	dek := dekOf(t, v, alice)
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	v = open(t, dir, a)
	defer func() { _ = v.Close() }()
	if got := resolve(t, v, "alice@example.com"); got != alice {
		t.Fatal("the ref changed across a reopen")
	}
	if !bytes.Equal(dekOf(t, v, alice), dek) {
		t.Fatal("the DEK changed across a reopen")
	}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path) // #nosec G304 G122 -- a test's own temporary directory
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte("alice")) || strings.Contains(path, "alice") {
			t.Errorf("%s holds the identifier", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Refs are 128 random bits, read from the random source and not derived from
// the identifier; the index is HMAC-SHA256 under the vault key (ADR-0011,
// ADR-0020).
//
// Seen failing with the index made SHA-256 of the identifier alone.
func TestRefsAreRandomAndTheIndexIsAnHMAC(t *testing.T) {
	dir := vaultDir(t)
	src := &seq{}
	v := open(t, dir, kek(t, "a", 1), WithRand(src))
	defer func() { _ = v.Close() }()
	// The source's first 32 bytes are the vault key; the next 16, the ref.
	vaultKey := make([]byte, 32)
	if _, err := (&seq{}).Read(vaultKey); err != nil {
		t.Fatal(err)
	}
	ref := resolve(t, v, "alice")
	var want tally.SubjectRef
	for i := range want {
		want[i] = byte(32 + i)
	}
	if ref != want {
		t.Fatalf("ref %x, want the source's bytes %x", ref, want)
	}

	mac := hmac.New(sha256.New, vaultKey)
	mac.Write([]byte("alice"))
	name := filepath.Join(dir, idxDir, hex.EncodeToString(mac.Sum(nil)))
	b, err := os.ReadFile(name) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatalf("no index file at HMAC(vault key, identifier): %v", err)
	}
	if got, err := decodeIdx(b); err != nil || got != ref {
		t.Fatalf("the index file holds %x, %v", got, err)
	}

	// Another vault, another source: another ref for the same identifier.
	other := open(t, vaultDir(t), kek(t, "a", 1))
	defer func() { _ = other.Close() }()
	if resolve(t, other, "alice") == ref {
		t.Fatal("the ref is the same in two vaults: it is derived, not random")
	}
}

// No key reaches fmt, under any verb, from the vault, a KEK, or a struct
// holding either; nor an error (RS-07). A FileVault cannot be copied by value
// (go vet: it holds a mutex), so only its pointer is printed.
//
// Seen failing with the local KEK's key held in a struct field.
func TestNoKeyIsPrinted(t *testing.T) {
	dir := vaultDir(t)
	kekKey := bytes.Repeat([]byte{0xAB}, 32)
	k, err := NewLocalKEK("a", kekKey)
	if err != nil {
		t.Fatal(err)
	}
	src := &seq{n: 0xC0}
	v := open(t, dir, k, WithRand(src))
	defer func() { _ = v.Close() }()
	ref := resolve(t, v, "alice")
	dek := dekOf(t, v, ref)

	vaultKey := make([]byte, 32)
	if _, err := (&seq{n: 0xC0}).Read(vaultKey); err != nil {
		t.Fatal(err)
	}
	secrets := [][]byte{kekKey[:8], dek[:8], vaultKey[:8]}
	// The bytes raw, in hex, as fmt prints a byte slice ("171 171"), and spaced.
	forms := func(b []byte) []string {
		dec := make([]string, len(b))
		for i, c := range b {
			dec[i] = fmt.Sprint(int(c))
		}
		return []string{string(b), hex.EncodeToString(b), strings.Join(dec, " "), fmt.Sprintf("% x", b)}
	}
	_, wrongErr := OpenFileVault(context.Background(), vaultDir(t)+"x", kek(t, "a", 9))
	_, unwrapErr := v.unwrap(context.Background(), "a", []byte("not a wrapped key at all, long enough"), nil)
	values := map[string]any{
		"*FileVault": v, "KEK": k,
		"struct{k KEK}": struct{ k KEK }{k}, "struct{v *FileVault}": struct{ v *FileVault }{v},
		"an error": unwrapErr, "another error": wrongErr,
	}
	checked := 0
	for name, val := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d"} {
			out := fmt.Sprintf(verb, val)
			checked++
			for _, s := range secrets {
				for _, f := range forms(s) {
					if strings.Contains(out, f) {
						t.Errorf("%s with %s prints a key (%q): %.200s", name, verb, f, out)
					}
				}
			}
		}
	}
	if checked != 36 {
		t.Fatalf("checked %d prints, want 36", checked)
	}
}

// RotateKEK rewraps every DEK and the vault key under the new KEK: afterwards
// the vault opens with the new KEK alone, refs and DEKs unchanged, and no
// longer with the old one (ADR-0020).
//
// Seen failing with VAULT left out of the rotation.
func TestRotateKEK(t *testing.T) {
	dir := vaultDir(t)
	a, b := kek(t, "a", 1), kek(t, "b", 2)
	v := open(t, dir, a)
	refs := map[string]tally.SubjectRef{}
	deks := map[tally.SubjectRef][]byte{}
	for i := range 5 {
		id := fmt.Sprintf("subject-%d", i)
		refs[id] = resolve(t, v, id)
		deks[refs[id]] = dekOf(t, v, refs[id])
	}
	if err := v.RotateKEK(context.Background(), b); err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}
	// A subject resolved after the rotation is wrapped under b too.
	refs["late"] = resolve(t, v, "late")
	deks[refs["late"]] = dekOf(t, v, refs["late"])
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	v = open(t, dir, b)
	for id, ref := range refs {
		if got := resolve(t, v, id); got != ref {
			t.Errorf("%s: ref changed", id)
		}
		if !bytes.Equal(dekOf(t, v, ref), deks[ref]) {
			t.Errorf("%s: DEK changed", id)
		}
	}
	_ = v.Close()

	if _, err := OpenFileVault(context.Background(), dir, a); !errors.Is(err, ErrUnknownKEK) {
		t.Fatalf("opening with the retired KEK = %v, want ErrUnknownKEK", err)
	}
}

// failRename fails the rename numbered at (1-based), so a rotation stops part
// way, as a crash would.
type failRename struct {
	fsx.FS
	at, n int
}

func (f *failRename) Rename(oldpath, newpath string) error {
	f.n++
	if f.n == f.at {
		return errors.New("injected crash")
	}
	return f.FS.Rename(oldpath, newpath)
}

// A rotation interrupted part way is resumed by calling RotateKEK again on a
// vault opened with both KEKs; every DEK survives, whichever file the
// interruption fell on.
//
// Seen failing with rewrapRef ignoring a file's recorded KEK id and
// unwrapping with the vault's current KEK.
func TestAnInterruptedRotationResumes(t *testing.T) {
	const subjects = 4
	ran := 0
	for at := 1; at <= subjects+1; at++ { // each ref file, then VAULT
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			ran++
			dir := vaultDir(t)
			a, b := kek(t, "a", 1), kek(t, "b", 2)
			v := open(t, dir, a)
			deks := map[tally.SubjectRef][]byte{}
			for i := range subjects {
				ref := resolve(t, v, fmt.Sprint(i))
				deks[ref] = dekOf(t, v, ref)
			}
			_ = v.Close()

			fr := &failRename{FS: fsx.OS{}, at: at}
			v = open(t, dir, a, func(c *config) { c.fsys = fr })
			if err := v.RotateKEK(context.Background(), b); err == nil {
				t.Fatal("the injected crash did not stop the rotation")
			}
			_ = v.Close()

			v = open(t, dir, b, WithKEKs(a))
			if err := v.RotateKEK(context.Background(), b); err != nil {
				t.Fatalf("resuming: %v", err)
			}
			_ = v.Close()

			v = open(t, dir, b)
			defer func() { _ = v.Close() }()
			for ref, dek := range deks {
				if !bytes.Equal(dekOf(t, v, ref), dek) {
					t.Errorf("a DEK changed or was lost")
				}
			}
		})
	}
	if ran != subjects+1 {
		t.Fatalf("ran %d interruptions, want %d", ran, subjects+1)
	}
}

// A wrapped DEK is bound to its ref by the AAD: moved into another ref's
// file, it does not unwrap (SPEC §4.1).
//
// Seen failing with the AAD of a DEK no longer naming its ref.
func TestAWrappedDEKIsBoundToItsRef(t *testing.T) {
	dir := vaultDir(t)
	v := open(t, dir, kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	alice, bob := resolve(t, v, "alice"), resolve(t, v, "bob")
	ab, err := os.ReadFile(filepath.Join(dir, refName(alice))) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, refName(bob)), ab, 0o600); err != nil { // #nosec G703 -- a test's own file
		t.Fatal(err)
	}
	if _, err := v.dek(context.Background(), bob); err == nil {
		t.Fatal("alice's wrapped DEK unwrapped as bob's")
	}
}

// The vault refuses a KEK it does not know, a directory others can access,
// and a second opener; its files are 0600 in 0700 directories (RS-10).
func TestOpenFileVaultRefuses(t *testing.T) {
	dir := vaultDir(t)
	v := open(t, dir, kek(t, "a", 1))
	resolve(t, v, "alice")

	if _, err := OpenFileVault(context.Background(), dir, kek(t, "a", 1)); !errors.Is(err, tally.ErrLocked) {
		t.Fatalf("a second open = %v, want tally.ErrLocked", err)
	}
	_ = v.Close()

	if _, err := OpenFileVault(context.Background(), dir, kek(t, "z", 1)); !errors.Is(err, ErrUnknownKEK) {
		t.Errorf("an unknown KEK = %v, want ErrUnknownKEK", err)
	}
	if _, err := OpenFileVault(context.Background(), dir, kek(t, "a", 7)); err == nil {
		t.Error("a KEK with the right id and the wrong key opened the vault")
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode %04o, want %04o", path, info.Mode().Perm(), want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil { // #nosec G302 -- the looser mode under test
		t.Fatal(err)
	}
	if _, err := OpenFileVault(context.Background(), dir, kek(t, "a", 1)); !errors.Is(err, ErrLoosePermissions) {
		t.Errorf("a 0750 directory = %v, want ErrLoosePermissions", err)
	}
}

// An index entry left without its ref's file, as a crash during a shred
// leaves it, resolves to a new ref rather than to a missing DEK.
func TestAnIndexWithoutItsRefResolvesAnew(t *testing.T) {
	dir := vaultDir(t)
	v := open(t, dir, kek(t, "a", 1))
	defer func() { _ = v.Close() }()
	old := resolve(t, v, "alice")
	if err := os.Remove(filepath.Join(dir, refName(old))); err != nil {
		t.Fatal(err)
	}
	if fresh := resolve(t, v, "alice"); fresh == old {
		t.Fatal("Resolve returned a ref whose DEK is gone")
	}
}
