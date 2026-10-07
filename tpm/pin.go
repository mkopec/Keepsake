package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// DefaultPINIndex is the NV index that stores the clientPIN state.
const DefaultPINIndex = 0x0100F1D1

// ErrLockout is returned when the TPM refuses to check the PIN because its
// dictionary attack protection is in lockout mode.
var ErrLockout = errors.New("TPM is in dictionary attack lockout")

// Layout of the PIN index data:
//
//	offset 0: remaining PIN retries
//	offset 1: big endian length of the UV key blob
//	offset 3: UV key blob
const (
	pinDataSize       = 384
	pinRetriesOffset  = 0
	uvKeyBlobOffset   = 1
	maxUVKeyBlobSize  = pinDataSize - uvKeyBlobOffset - 2
	uvKeyBlobLenBytes = 2
)

// The PIN index's authValue is the PIN hash. The owner can read and write
// its data; reading the index with its own authValue proves knowledge of
// the PIN. NoDA is clear so wrong PINs count towards the TPM's dictionary
// attack lockout, which limits guessing even when bypassing tpm-fido.
func pinNVPublic(index uint32) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMIRHNVIndex(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			AuthRead:   true,
			NT:         tpm2.TPMNTOrdinary,
		},
		DataSize: pinDataSize,
	}
}

var ownerAuth = tpm2.AuthHandle{
	Handle: tpm2.TPMRHOwner,
	Auth:   tpm2.PasswordAuth(nil),
}

// pinIndex returns the name of the PIN index and whether it exists. An index
// that exists but was never written is left over from an interrupted SetPIN
// and doesn't hold a PIN.
func (t *TPM) pinIndex(tpm transport.TPM) (name tpm2.TPM2BName, exists, written bool, err error) {
	rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(t.pinIndexHandle)}.Execute(tpm)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return name, false, false, nil
	}
	if err != nil {
		return name, false, false, fmt.Errorf("read PIN index public err: %w", err)
	}

	pub, err := rsp.NVPublic.Contents()
	if err != nil {
		return name, false, false, err
	}
	want := pinNVPublic(t.pinIndexHandle)
	attrs := pub.Attributes
	written = attrs.Written
	attrs.Written = false
	if attrs != want.Attributes || pub.DataSize != want.DataSize || pub.NameAlg != want.NameAlg {
		return name, false, false, fmt.Errorf("NV index 0x%08x exists but is not a tpm-fido PIN index", t.pinIndexHandle)
	}

	return rsp.NVName, true, written, nil
}

// pinIndexWritten returns the name of the PIN index, or an error if no PIN
// is set.
func (t *TPM) pinIndexWritten(tpm transport.TPM) (tpm2.TPM2BName, error) {
	name, _, written, err := t.pinIndex(tpm)
	if err != nil {
		return name, err
	}
	if !written {
		return name, errors.New("PIN not set")
	}
	return name, nil
}

func (t *TPM) pinIndexHandleNamed(name tpm2.TPM2BName) tpm2.NamedHandle {
	return tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.pinIndexHandle), Name: name}
}

func (t *TPM) withTPM(f func(tpm transport.TPM) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	rwc, err := t.open()
	if err != nil {
		return fmt.Errorf("open tpm err: %w", err)
	}
	defer rwc.Close()

	return f(transport.FromReadWriter(rwc))
}

// PINSet reports whether a PIN has been set.
func (t *TPM) PINSet() (bool, error) {
	var set bool
	err := t.withTPM(func(tpm transport.TPM) error {
		var err error
		_, _, set, err = t.pinIndex(tpm)
		return err
	})
	return set, err
}

// SetPIN stores pinHash as the PIN and sets the retries counter to
// retries. When changing the PIN, oldPinHash must be the current PIN hash so
// the UV key can be re-wrapped; otherwise it is nil and a new UV key is
// created.
func (t *TPM) SetPIN(pinHash, oldPinHash []byte, retries int) error {
	return t.withTPM(func(tpm transport.TPM) error {
		name, exists, written, err := t.pinIndex(tpm)
		if err != nil {
			return err
		}

		sec, err := t.secure(tpm)
		if err != nil {
			return err
		}
		defer sec.close()

		var blob []byte
		if written && oldPinHash != nil {
			old, err := t.readUVKeyBlob(tpm, name)
			if err != nil {
				return err
			}
			if blob, err = changeUVKeyAuth(sec, old, oldPinHash, pinHash); err != nil {
				return err
			}
		} else if blob, err = createUVKey(sec, pinHash); err != nil {
			return err
		}

		if exists {
			_, err = tpm2.NVUndefineSpace{
				AuthHandle: ownerAuth,
				NVIndex:    t.pinIndexHandleNamed(name),
			}.Execute(tpm)
			if err != nil {
				return fmt.Errorf("undefine PIN index err: %w", err)
			}
		}

		// the PIN hash is the first parameter, encrypted
		_, err = tpm2.NVDefineSpace{
			AuthHandle: ownerAuth,
			Auth:       tpm2.TPM2BAuth{Buffer: pinHash},
			PublicInfo: tpm2.New2B(pinNVPublic(t.pinIndexHandle)),
		}.Execute(tpm, sec.encrypt(encryptIn))
		if err != nil {
			return fmt.Errorf("define PIN index 0x%08x (requires empty owner auth) err: %w", t.pinIndexHandle, err)
		}

		name, _, _, err = t.pinIndex(tpm)
		if err != nil {
			return err
		}

		data := make([]byte, pinDataSize)
		data[pinRetriesOffset] = byte(retries)
		binary.BigEndian.PutUint16(data[uvKeyBlobOffset:], uint16(len(blob)))
		copy(data[uvKeyBlobOffset+uvKeyBlobLenBytes:], blob)
		_, err = tpm2.NVWrite{
			AuthHandle: ownerAuth,
			NVIndex:    t.pinIndexHandleNamed(name),
			Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("write PIN index err: %w", err)
		}
		return nil
	})
}

// PINRetries returns the remaining PIN retries.
func (t *TPM) PINRetries() (int, error) {
	var retries int
	err := t.withTPM(func(tpm transport.TPM) error {
		name, err := t.pinIndexWritten(tpm)
		if err != nil {
			return err
		}
		rsp, err := tpm2.NVRead{
			AuthHandle: ownerAuth,
			NVIndex:    t.pinIndexHandleNamed(name),
			Size:       1,
			Offset:     pinRetriesOffset,
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("read PIN retries err: %w", err)
		}
		retries = int(rsp.Data.Buffer[0])
		return nil
	})
	return retries, err
}

// SetPINRetries stores the remaining PIN retries.
func (t *TPM) SetPINRetries(retries int) error {
	return t.withTPM(func(tpm transport.TPM) error {
		name, err := t.pinIndexWritten(tpm)
		if err != nil {
			return err
		}
		_, err = tpm2.NVWrite{
			AuthHandle: ownerAuth,
			NVIndex:    t.pinIndexHandleNamed(name),
			Data:       tpm2.TPM2BMaxNVBuffer{Buffer: []byte{byte(retries)}},
			Offset:     pinRetriesOffset,
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("write PIN retries err: %w", err)
		}
		return nil
	})
}

// VerifyPIN reports whether pinHash matches the stored PIN. It doesn't
// touch the retries counter. It returns ErrLockout if the TPM is in
// dictionary attack lockout.
func (t *TPM) VerifyPIN(pinHash []byte) (bool, error) {
	var match bool
	err := t.withTPM(func(tpm transport.TPM) error {
		name, err := t.pinIndexWritten(tpm)
		if err != nil {
			return err
		}
		sec, err := t.secure(tpm)
		if err != nil {
			return err
		}
		defer sec.close()
		_, err = tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(t.pinIndexHandle),
				Name:   name,
				Auth:   sec.auth(pinHash),
			},
			NVIndex: t.pinIndexHandleNamed(name),
			Size:    1,
		}.Execute(tpm)
		match, err = classifyAuthErr(err)
		if err != nil {
			return fmt.Errorf("verify PIN err: %w", err)
		}
		return nil
	})
	return match, err
}

// classifyAuthErr maps the result of a command authorized with the PIN hash
// to whether the PIN matched.
func classifyAuthErr(err error) (bool, error) {
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth):
		return false, nil
	case errors.Is(err, tpm2.TPMRCLockout):
		return false, ErrLockout
	}
	return false, err
}

func (t *TPM) readUVKeyBlob(tpm transport.TPM, name tpm2.TPM2BName) ([]byte, error) {
	rsp, err := tpm2.NVRead{
		AuthHandle: ownerAuth,
		NVIndex:    t.pinIndexHandleNamed(name),
		Size:       pinDataSize - uvKeyBlobOffset,
		Offset:     uvKeyBlobOffset,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("read UV key err: %w", err)
	}
	data := rsp.Data.Buffer
	n := int(binary.BigEndian.Uint16(data))
	if n == 0 || n > len(data)-uvKeyBlobLenBytes {
		return nil, errors.New("no UV key in PIN index")
	}
	return data[uvKeyBlobLenBytes : uvKeyBlobLenBytes+n], nil
}
