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
	// persistent SRKs aren't flushed
	persistent bool
}

// Creating the SRK (an ECC primary key) is one of the slowest TPM
// operations, and tpm-fido needs it several times per request. If the TPM
// has a persistent SRK with the same (deterministic) template, it is used
// instead: at the handles TCG's provisioning guidance and systemd use, or
// at tpm-fido's own handle, where tpm-fido persists it if neither exists.
// The SRK carries no secrets; it is shared by all users.
var srkHandles = []uint32{0x81000001, 0x81000002}

const tpmFidoSRKHandle = 0x81310000

// secure loads the SRK and checks it against the pinned name. The caller
// must call close.
func (t *TPM) secure(tpm transport.TPM) (*secure, error) {
	if t.srkHandle != 0 {
		rsp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(t.srkHandle)}.Execute(tpm)
		if err == nil {
			if pub, err := rsp.OutPublic.Contents(); err == nil {
				if name, err := tpm2.ObjectName(pub); err == nil && subtle.ConstantTimeCompare(name.Buffer, t.srkName) == 1 {
					srk := &tpm2.CreatePrimaryResponse{ObjectHandle: tpm2.TPMHandle(t.srkHandle), Name: *name, OutPublic: rsp.OutPublic}
					return &secure{tpm: tpm, srk: srk, pub: *pub, persistent: true}, nil
				}
			}
		}
		// evicted or replaced: fall back to creating it
		t.srkHandle = 0
	}
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
	if !s.persistent {
		flush(s.tpm, s.srk.ObjectHandle)
	}
}

// findPersistentSRK looks for a persistent SRK with the pinned name, and
// persists sec's SRK at tpm-fido's handle if there is none.
func (t *TPM) findPersistentSRK(tpm transport.TPM, sec *secure) {
	for _, h := range append(srkHandles, tpmFidoSRKHandle) {
		rsp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(h)}.Execute(tpm)
		if err != nil {
			continue
		}
		pub, err := rsp.OutPublic.Contents()
		if err != nil {
			continue
		}
		if name, err := tpm2.ObjectName(pub); err == nil && bytes.Equal(name.Buffer, t.srkName) {
			t.srkHandle = h
			return
		}
	}
	if sec.persistent {
		return
	}
	_, err := tpm2.EvictControl{
		Auth:             ownerAuth,
		ObjectHandle:     tpm2.NamedHandle{Handle: sec.srk.ObjectHandle, Name: sec.srk.Name},
		PersistentHandle: tpm2.TPMIDHPersistent(tpmFidoSRKHandle),
	}.Execute(tpm)
	if err == nil {
		t.srkHandle = tpmFidoSRKHandle
	}
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
		t.findPersistentSRK(tpm, s)
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
	t.findPersistentSRK(tpm, s)
	return nil
}
