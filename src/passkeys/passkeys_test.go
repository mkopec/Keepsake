package passkeys

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func testStore(t *testing.T, key []byte) *Store {
	return &Store{
		Path: filepath.Join(t.TempDir(), "sub", "passkeys"),
		Key:  func() ([]byte, error) { return key, nil },
	}
}

func TestRoundTrip(t *testing.T) {
	s := testStore(t, bytes.Repeat([]byte{1}, 32))

	creds, err := s.Load()
	if err != nil || creds != nil {
		t.Fatalf("missing store: %v %v", creds, err)
	}

	want := []Credential{{ID: []byte{1, 2}, RPID: "example.com", UserID: []byte{3}, UserName: "alice", PublicKey: []byte{4}, Created: 42}}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(s.Path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("store mode %v", info.Mode())
	}
	dir, _ := os.Stat(filepath.Dir(s.Path))
	if dir.Mode().Perm() != 0700 {
		t.Fatalf("dir mode %v", dir.Mode())
	}

	got, err := s.Load()
	if err != nil || len(got) != 1 || got[0].RPID != "example.com" || got[0].UserName != "alice" || got[0].Created != 42 {
		t.Fatalf("got %+v %v", got, err)
	}

	raw, _ := os.ReadFile(s.Path)
	if bytes.Contains(raw, []byte("example.com")) || bytes.Contains(raw, []byte("alice")) {
		t.Fatal("store isn't encrypted")
	}

	if err := s.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(); err != nil {
		t.Fatalf("removing a missing store: %v", err)
	}
}

func TestUndecryptable(t *testing.T) {
	s := testStore(t, bytes.Repeat([]byte{1}, 32))
	if err := s.Save([]Credential{{ID: []byte{1}}}); err != nil {
		t.Fatal(err)
	}

	other := &Store{Path: s.Path, Key: func() ([]byte, error) { return bytes.Repeat([]byte{2}, 32), nil }}
	if _, err := other.Load(); err != ErrUndecryptable {
		t.Fatalf("wrong key: %v", err)
	}

	raw, _ := os.ReadFile(s.Path)
	raw[len(raw)-1] ^= 1
	os.WriteFile(s.Path, raw, 0600)
	if _, err := s.Load(); err != ErrUndecryptable {
		t.Fatalf("tampered store: %v", err)
	}

	name, err := s.MoveAside("x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(name); err != nil {
		t.Fatal(err)
	}
	if creds, err := s.Load(); err != nil || creds != nil {
		t.Fatalf("after moving aside: %v %v", creds, err)
	}
}

func TestMaxCredentials(t *testing.T) {
	s := testStore(t, bytes.Repeat([]byte{1}, 32))
	if err := s.Save(make([]Credential, MaxCredentials+1)); err == nil {
		t.Fatal("saved too many credentials")
	}
}

type counter struct{ v uint64 }

func (c *counter) store(t *testing.T, path string) *Store {
	return &Store{
		Path:    path,
		Key:     func() ([]byte, error) { return bytes.Repeat([]byte{1}, 32), nil },
		Version: func() (uint64, error) { return c.v, nil },
		Advance: func(v uint64) error {
			if v != c.v+1 {
				t.Fatalf("advance %d -> %d", c.v, v)
			}
			c.v = v
			return nil
		},
	}
}

func TestRollback(t *testing.T) {
	c := &counter{v: 41}
	path := filepath.Join(t.TempDir(), "passkeys")
	s := c.store(t, path)

	if err := s.Save([]Credential{{ID: []byte{1}}}); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(path)
	if err := s.Save([]Credential{{ID: []byte{1}}, {ID: []byte{2}}}); err != nil {
		t.Fatal(err)
	}
	if c.v != 43 {
		t.Fatalf("counter %d", c.v)
	}
	if creds, err := s.Load(); err != nil || len(creds) != 2 {
		t.Fatalf("load: %v %v", creds, err)
	}

	// restoring the older copy is detected
	os.WriteFile(path, old, 0600)
	if _, err := s.Load(); err != ErrRolledBack {
		t.Fatalf("rollback: %v", err)
	}

	// tampering with the version breaks authentication
	cur, _ := os.ReadFile(path)
	cur[len(headerV2)+7]++
	os.WriteFile(path, cur, 0600)
	if _, err := s.Load(); err != ErrUndecryptable {
		t.Fatalf("modified version: %v", err)
	}
}

func TestCrashBeforeAdvance(t *testing.T) {
	c := &counter{v: 5}
	path := filepath.Join(t.TempDir(), "passkeys")
	s := c.store(t, path)
	if err := s.Save([]Credential{{ID: []byte{1}}}); err != nil {
		t.Fatal(err)
	}
	// simulate a crash after writing the store and before advancing
	c.v--
	if creds, err := s.Load(); err != nil || len(creds) != 1 || c.v != 6 {
		t.Fatalf("load after crash: %v %v counter %d", creds, err, c.v)
	}
}

func TestUnversionedMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "passkeys")
	plain := &Store{Path: path, Key: func() ([]byte, error) { return bytes.Repeat([]byte{1}, 32), nil }}
	// write a v1 store by hand
	aead, _ := plain.aead()
	nonce := make([]byte, aead.NonceSize())
	pt, _ := cbor.Marshal([]Credential{{ID: []byte{7}}})
	data := append(append([]byte(nil), headerV1...), nonce...)
	os.WriteFile(path, aead.Seal(data, nonce, pt, headerV1), 0600)

	c := &counter{v: 1}
	s := c.store(t, path)
	if _, err := s.Load(); err != ErrRolledBack {
		t.Fatalf("v1 store accepted without AllowUnversioned: %v", err)
	}
	s.AllowUnversioned = true
	creds, err := s.Load()
	if err != nil || len(creds) != 1 {
		t.Fatalf("migration load: %v %v", creds, err)
	}
}
