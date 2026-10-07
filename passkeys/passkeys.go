// passkeys stores the metadata of discoverable credentials.
//
// The credentials themselves are self-contained TPM key handles; the store
// only makes them discoverable (and, for credentials flagged as
// discoverable, usable: tpm-fido refuses a discoverable credential that
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

var header = []byte("tpm-fido passkeys v1\n")

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
}

// DefaultPath returns $XDG_DATA_HOME/tpm-fido/passkeys.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "tpm-fido", "passkeys"), nil
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
	if !bytes.HasPrefix(data, header) || len(data) < len(header)+aead.NonceSize() {
		return nil, ErrUndecryptable
	}
	nonce := data[len(header) : len(header)+aead.NonceSize()]
	plain, err := aead.Open(nil, nonce, data[len(header)+aead.NonceSize():], header)
	if err != nil {
		return nil, ErrUndecryptable
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
	data := append(append([]byte(nil), header...), nonce...)
	data = aead.Seal(data, nonce, plain, header)

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
	return os.Rename(tmp.Name(), s.Path)
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
