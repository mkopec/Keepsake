package tpm

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Commands that carry secrets (PIN hashes, hmac-secret outputs, the passkey
// store key) use HMAC sessions salted with the storage root key (SRK), with
// parameter encryption where the secret is a command or response parameter.
// Someone recording the bus between the CPU and a discrete TPM then sees
// neither the PIN hash nor anything to brute force it from.
//
// Salting only helps if the SRK public key is the TPM's: an active
// interposer could substitute its own. The SRK's name is pinned on first
// use (trust on first use) in a file, and every later session checks the
// SRK against it.

// ErrSRKMismatch is returned when the TPM's storage root key doesn't match
// the pinned one.
var ErrSRKMismatch = errors.New("the TPM's storage root key changed")

// secure is a loaded SRK for salting sessions on one TPM connection.
type secure struct {
	tpm transport.TPM
	srk *tpm2.CreatePrimaryResponse
	pub tpm2.TPMTPublic
}

// secure loads the SRK and checks it against the pinned name. The caller
// must call close.
func (t *TPM) secure(tpm transport.TPM) (*secure, error) {
	srk, err := createSRK(tpm)
	if err != nil {
		return nil, err
	}
	pub, err := srk.OutPublic.Contents()
	if err != nil {
		flush(tpm, srk.ObjectHandle)
		return nil, err
	}
	// Compute the name from the public area instead of trusting the
	// returned one.
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		flush(tpm, srk.ObjectHandle)
		return nil, err
	}
	if t.srkName != nil && subtle.ConstantTimeCompare(name.Buffer, t.srkName) != 1 {
		flush(tpm, srk.ObjectHandle)
		return nil, ErrSRKMismatch
	}
	return &secure{tpm: tpm, srk: srk, pub: *pub}, nil
}

func (s *secure) close() {
	flush(s.tpm, s.srk.ObjectHandle)
}

// auth returns a one-time salted HMAC session proving knowledge of
// authValue, optionally encrypting the first command and/or response
// parameter.
func (s *secure) auth(authValue []byte, enc ...tpm2.AuthOption) tpm2.Session {
	opts := append([]tpm2.AuthOption{tpm2.Auth(authValue), tpm2.Salted(s.srk.ObjectHandle, s.pub)}, enc...)
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, opts...)
}

// encrypt returns a one-time salted session that only encrypts parameters,
// for commands authorized with a password session.
func (s *secure) encrypt(enc tpm2.AuthOption) tpm2.Session {
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Salted(s.srk.ObjectHandle, s.pub), enc)
}

var (
	encryptIn  = tpm2.AESEncryption(128, tpm2.EncryptIn)
	encryptOut = tpm2.AESEncryption(128, tpm2.EncryptOut)
)

// pinSRK loads the pinned SRK name from path, or pins the current one if
// the file doesn't exist. An empty path disables pinning.
func (t *TPM) pinSRK(tpm transport.TPM, path string) error {
	if path == "" {
		return nil
	}
	s, err := t.secure(tpm)
	if err != nil {
		return err
	}
	defer s.close()
	name, err := tpm2.ObjectName(&s.pub)
	if err != nil {
		return err
	}

	pinned, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, name.Buffer, 0600); err != nil {
			return fmt.Errorf("pin SRK err: %w", err)
		}
		t.srkName = name.Buffer
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(pinned, name.Buffer) {
		return fmt.Errorf("%w: either the TPM was cleared, which also destroyed all tpm-fido credentials, "+
			"or something between the CPU and the TPM is intercepting its traffic. If you cleared the TPM, "+
			"delete %s", ErrSRKMismatch, path)
	}
	t.srkName = pinned
	return nil
}
