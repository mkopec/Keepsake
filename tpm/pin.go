package tpm

import (
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

// The PIN index's authValue is the PIN hash and its single byte of data is
// the remaining PIN retries. The owner can read and write the retries
// counter; reading the index with its own authValue proves knowledge of the
// PIN. NoDA is clear so wrong PINs count towards the TPM's dictionary attack
// lockout, which limits guessing even when bypassing tpm-fido.
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
		DataSize: 1,
	}
}

var ownerAuth = tpm2.AuthHandle{
	Handle: tpm2.TPMRHOwner,
	Auth:   tpm2.PasswordAuth(nil),
}

// pinIndex returns the name of the PIN index, or ok=false if no PIN is set.
func (t *TPM) pinIndex(tpm transport.TPM) (name tpm2.TPM2BName, ok bool, err error) {
	rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(t.pinIndexHandle)}.Execute(tpm)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return name, false, nil
	}
	if err != nil {
		return name, false, fmt.Errorf("read PIN index public err: %w", err)
	}

	pub, err := rsp.NVPublic.Contents()
	if err != nil {
		return name, false, err
	}
	want := pinNVPublic(t.pinIndexHandle)
	attrs := pub.Attributes
	written := attrs.Written
	attrs.Written = false
	if attrs != want.Attributes || pub.DataSize != want.DataSize || pub.NameAlg != want.NameAlg {
		return name, false, fmt.Errorf("NV index 0x%08x exists but is not a tpm-fido PIN index", t.pinIndexHandle)
	}

	// An index that was never written is left over from an interrupted
	// SetPIN.
	return rsp.NVName, written, nil
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
		_, set, err = t.pinIndex(tpm)
		return err
	})
	return set, err
}

// SetPIN stores pinHash as the PIN, replacing any existing PIN, and sets the
// retries counter to retries.
func (t *TPM) SetPIN(pinHash []byte, retries int) error {
	return t.withTPM(func(tpm transport.TPM) error {
		_, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(t.pinIndexHandle)}.Execute(tpm)
		if err == nil {
			// pinIndex checks the index is ours before deleting it
			name, _, err := t.pinIndex(tpm)
			if err != nil {
				return err
			}
			_, err = tpm2.NVUndefineSpace{
				AuthHandle: ownerAuth,
				NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.pinIndexHandle), Name: name},
			}.Execute(tpm)
			if err != nil {
				return fmt.Errorf("undefine PIN index err: %w", err)
			}
		} else if !errors.Is(err, tpm2.TPMRCHandle) {
			return fmt.Errorf("read PIN index public err: %w", err)
		}

		_, err = tpm2.NVDefineSpace{
			AuthHandle: ownerAuth,
			Auth:       tpm2.TPM2BAuth{Buffer: pinHash},
			PublicInfo: tpm2.New2B(pinNVPublic(t.pinIndexHandle)),
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("define PIN index 0x%08x (requires empty owner auth) err: %w", t.pinIndexHandle, err)
		}

		name, _, err := t.pinIndex(tpm)
		if err != nil {
			return err
		}
		return t.writeRetries(tpm, name, retries)
	})
}

// PINRetries returns the remaining PIN retries.
func (t *TPM) PINRetries() (int, error) {
	var retries int
	err := t.withTPM(func(tpm transport.TPM) error {
		name, ok, err := t.pinIndex(tpm)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("PIN not set")
		}
		rsp, err := tpm2.NVRead{
			AuthHandle: ownerAuth,
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.pinIndexHandle), Name: name},
			Size:       1,
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
		name, ok, err := t.pinIndex(tpm)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("PIN not set")
		}
		return t.writeRetries(tpm, name, retries)
	})
}

func (t *TPM) writeRetries(tpm transport.TPM, name tpm2.TPM2BName, retries int) error {
	_, err := tpm2.NVWrite{
		AuthHandle: ownerAuth,
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.pinIndexHandle), Name: name},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: []byte{byte(retries)}},
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("write PIN retries err: %w", err)
	}
	return nil
}

// VerifyPIN reports whether pinHash matches the stored PIN. It doesn't
// touch the retries counter. It returns ErrLockout if the TPM is in
// dictionary attack lockout.
func (t *TPM) VerifyPIN(pinHash []byte) (bool, error) {
	var match bool
	err := t.withTPM(func(tpm transport.TPM) error {
		name, ok, err := t.pinIndex(tpm)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("PIN not set")
		}
		_, err = tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(t.pinIndexHandle),
				Name:   name,
				Auth:   tpm2.PasswordAuth(pinHash),
			},
			NVIndex: tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.pinIndexHandle), Name: name},
			Size:    1,
		}.Execute(tpm)
		switch {
		case err == nil:
			match = true
		case errors.Is(err, tpm2.TPMRCAuthFail), errors.Is(err, tpm2.TPMRCBadAuth):
			match = false
		case errors.Is(err, tpm2.TPMRCLockout):
			return ErrLockout
		default:
			return fmt.Errorf("verify PIN err: %w", err)
		}
		return nil
	})
	return match, err
}
