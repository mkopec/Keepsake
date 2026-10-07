package passkeys

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
