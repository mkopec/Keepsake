// passkeys stores the metadata of discoverable credentials.
//
// The credentials themselves are self-contained TPM key handles; the store
// only makes them discoverable (and, for credentials flagged as
// discoverable, usable: Keepsake refuses a discoverable credential that
// isn't in the store, so deleting it revokes it). The store is a single
// file encrypted with AES-256-GCM under a key derived from the TPM device
// key, so it can only be read on this TPM and becomes unreadable after a
// reset.
package passkeys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
)

// MaxCredentials is the maximum number of passkeys.
const MaxCredentials = 128

// ErrUndecryptable is returned by Load when the store exists but can't be
// decrypted, e.g. because the TPM was cleared or reset.
var ErrUndecryptable = errors.New("passkey store can't be decrypted")

// ErrRolledBack is returned by Load when the store is older than the last
// one saved, e.g. restored from a backup. It could contain deleted, i.e.
// revoked, passkeys.
var ErrRolledBack = errors.New("passkey store is older than the last saved one")

// v1 stores aren't versioned; v2 stores record the value of a counter
// (see Store.Version) after the header, authenticated with the contents.
var (
	headerV1 = []byte("tpm-fido passkeys v1\n")
	headerV2 = []byte("tpm-fido passkeys v2\n")
)

type Credential struct {
	ID              []byte `cbor:"1,keyasint"`
	RPID            string `cbor:"2,keyasint"`
	RPName          string `cbor:"3,keyasint,omitempty"`
	UserID          []byte `cbor:"4,keyasint"`
	UserName        string `cbor:"5,keyasint,omitempty"`
	UserDisplayName string `cbor:"6,keyasint,omitempty"`
	// COSE_Key encoded public key
	PublicKey []byte `cbor:"7,keyasint"`
	// unix time
	Created int64 `cbor:"8,keyasint"`
}

type Store struct {
	Path string
	// Key returns the 32 byte encryption key.
	Key func() ([]byte, error)

	// Version returns the current value of a monotonic counter, and
	// Advance increments it to the given value (Version()+1). Without
	// them the store isn't protected against rollback.
	Version func() (uint64, error)
	Advance func(uint64) error
	// AllowUnversioned accepts a v1 store once, to migrate it.
	AllowUnversioned bool
}

// DefaultPath returns $XDG_DATA_HOME/keepsake/passkeys.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "keepsake", "passkeys"), nil
}

// MigrateDataDir moves the data directory of versions named tpm-fido
// ($XDG_DATA_HOME/tpm-fido) to the directory of path, if that doesn't exist
// yet. It holds the user secret: without it, no credential can be used.
func MigrateDataDir(path string) (bool, error) {
	newDir := filepath.Dir(path)
	oldDir := filepath.Join(filepath.Dir(newDir), "tpm-fido")
	if _, err := os.Lstat(newDir); err == nil || !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	fi, err := os.Lstat(oldDir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, nil
	}
	return true, os.Rename(oldDir, newDir)
}

func (s *Store) aead() (cipher.AEAD, error) {
	key, err := s.Key()
	if err != nil {
		return nil, fmt.Errorf("passkey store key err: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Load returns the stored credentials. A missing store holds no
// credentials.
func (s *Store) Load() ([]Credential, error) {
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	aead, err := s.aead()
	if err != nil {
		return nil, err
	}
	var (
		aad       []byte
		version   uint64
		versioned bool
	)
	switch {
	case bytes.HasPrefix(data, headerV2) && len(data) >= len(headerV2)+8:
		aad = data[:len(headerV2)+8]
		version = binary.BigEndian.Uint64(data[len(headerV2):])
		versioned = true
	case bytes.HasPrefix(data, headerV1):
		aad = headerV1
	default:
		return nil, ErrUndecryptable
	}
	rest := data[len(aad):]
	if len(rest) < aead.NonceSize() {
		return nil, ErrUndecryptable
	}
	plain, err := aead.Open(nil, rest[:aead.NonceSize()], rest[aead.NonceSize():], aad)
	if err != nil {
		return nil, ErrUndecryptable
	}

	if s.Version != nil {
		if !versioned {
			if !s.AllowUnversioned {
				return nil, ErrRolledBack
			}
		} else {
			cur, err := s.Version()
			if err != nil {
				return nil, err
			}
			switch version {
			case cur:
			case cur + 1:
				// saved, but the counter wasn't advanced (crash)
				if err := s.Advance(version); err != nil {
					return nil, err
				}
			default:
				return nil, ErrRolledBack
			}
		}
	}

	var creds []Credential
	if err := cbor.Unmarshal(plain, &creds); err != nil {
		return nil, fmt.Errorf("decode passkey store err: %w", err)
	}
	return creds, nil
}

// Save replaces the stored credentials.
func (s *Store) Save(creds []Credential) error {
	if len(creds) > MaxCredentials {
		return fmt.Errorf("too many passkeys: %d", len(creds))
	}
	plain, err := cbor.Marshal(creds)
	if err != nil {
		return err
	}
	aead, err := s.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	var version uint64
	if s.Version != nil {
		cur, err := s.Version()
		if err != nil {
			return err
		}
		version = cur + 1
	}
	aad := binary.BigEndian.AppendUint64(append([]byte(nil), headerV2...), version)
	data := append(append([]byte(nil), aad...), nonce...)
	data = aead.Seal(data, nonce, plain, aad)

	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".passkeys-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.Path); err != nil {
		return err
	}
	// The store is written before the counter is advanced: after a crash
	// in between, Load sees a store one ahead and advances the counter.
	if s.Version != nil {
		return s.Advance(version)
	}
	return nil
}

// Remove deletes the store.
func (s *Store) Remove() error {
	err := os.Remove(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// MoveAside renames an undecryptable store so a new one can be created, and
// returns the new name.
func (s *Store) MoveAside(suffix string) (string, error) {
	name := s.Path + ".undecryptable-" + suffix
	return name, os.Rename(s.Path, name)
}
