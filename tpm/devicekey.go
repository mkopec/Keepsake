package tpm

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// The device key is a keyed hash key that every credential created by this
// version depends on: credential seeds, the hmac-secret secrets without user
// verification and the passkey store key are HMACs computed with it.
//
// It is created with a TPM generated sensitive value, made persistent and
// its wrapped private area is discarded, so it can't be loaded again once it
// is evicted. Evicting it (authenticatorReset) irrecoverably invalidates all
// credentials that depend on it. It has an empty authValue: like the
// credential keys themselves, anyone who can use the TPM can use it.

// state flags
const stateLegacyDisabled = 0x01

func deviceKeyTemplate() tpm2.TPMTPublic {
	return hmacKeyTemplate(true)
}

func stateNVPublic(index uint32) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMIRHNVIndex(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			NoDA:       true,
			NT:         tpm2.TPMNTOrdinary,
		},
		DataSize: 1,
	}
}

// ensureDeviceKey creates the device key if it doesn't exist and caches its
// name.
func (t *TPM) ensureDeviceKey(tpm transport.TPM) error {
	rsp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(t.deviceKeyHandle)}.Execute(tpm)
	if err == nil {
		pub, err := rsp.OutPublic.Contents()
		if err != nil {
			return err
		}
		want := deviceKeyTemplate()
		if pub.Type != want.Type || pub.NameAlg != want.NameAlg || pub.ObjectAttributes != want.ObjectAttributes {
			return fmt.Errorf("persistent handle 0x%08x is in use by an object that isn't a tpm-fido device key", t.deviceKeyHandle)
		}
		t.deviceKeyName = rsp.Name
		return t.checkDeviceKeyOwner(tpm)
	}
	if !errors.Is(err, tpm2.TPMRCHandle) {
		return fmt.Errorf("read device key err: %w", err)
	}
	return t.createDeviceKey(tpm)
}

func (t *TPM) createDeviceKey(tpm transport.TPM) error {
	sec, err := t.secure(tpm)
	if err != nil {
		return err
	}
	defer sec.close()
	srk := sec.srk

	// the authorization value is the first parameter, encrypted
	created, err := tpm2.Create{
		ParentHandle: srkParent(srk),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: t.deviceKeyAuth()},
			},
		},
		InPublic: tpm2.New2B(deviceKeyTemplate()),
	}.Execute(tpm, sec.encrypt(encryptIn))
	if err != nil {
		return fmt.Errorf("create device key err: %w", err)
	}
	loaded, err := tpm2.Load{
		ParentHandle: srkParent(srk),
		InPrivate:    created.OutPrivate,
		InPublic:     created.OutPublic,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("load device key err: %w", err)
	}
	defer flush(tpm, loaded.ObjectHandle)

	_, err = tpm2.EvictControl{
		Auth:             ownerAuth,
		ObjectHandle:     tpm2.NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name},
		PersistentHandle: tpm2.TPMIDHPersistent(t.deviceKeyHandle),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("persist device key at 0x%08x (requires empty owner auth) err: %w", t.deviceKeyHandle, err)
	}
	t.deviceKeyName = loaded.Name
	return nil
}

// deviceHMAC computes HMAC-SHA-256 of msg with the device key. With
// encrypt, the result is encrypted on the bus.
func (t *TPM) deviceHMAC(tpm transport.TPM, msg []byte, encrypt bool) ([]byte, error) {
	// An HMAC session proves knowledge of the authorization value without
	// sending it. It is high entropy, so the session doesn't need to be
	// salted unless the result must be encrypted.
	auth := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(t.deviceKeyAuth()))
	if encrypt {
		sec, err := t.secure(tpm)
		if err != nil {
			return nil, err
		}
		defer sec.close()
		auth = sec.auth(t.deviceKeyAuth(), encryptOut)
	}
	rsp, err := tpm2.Hmac{
		Handle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(t.deviceKeyHandle),
			Name:   t.deviceKeyName,
			Auth:   auth,
		},
		Buffer:  tpm2.TPM2BMaxBuffer{Buffer: msg},
		HashAlg: tpm2.TPMAlgSHA256,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("device key HMAC err: %w", err)
	}
	return rsp.OutHMAC.Buffer, nil
}

// StoreKey returns the key used to encrypt the passkey store.
func (t *TPM) StoreKey() ([]byte, error) {
	var key []byte
	err := t.withTPM(func(tpm transport.TPM) error {
		var err error
		key, err = t.deviceHMAC(tpm, []byte("tpm-fido passkey store key"), true)
		return err
	})
	return key, err
}

// readState returns the state flags. A missing state index means no flags.
func (t *TPM) readState(tpm transport.TPM) (byte, error) {
	pub, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(t.stateIndex)}.Execute(tpm)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read state index public err: %w", err)
	}
	contents, err := pub.NVPublic.Contents()
	if err != nil {
		return 0, err
	}
	if !contents.Attributes.Written {
		return 0, nil
	}
	rsp, err := tpm2.NVRead{
		AuthHandle: ownerAuth,
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.stateIndex), Name: pub.NVName},
		Size:       1,
	}.Execute(tpm)
	if err != nil {
		return 0, fmt.Errorf("read state err: %w", err)
	}
	return rsp.Data.Buffer[0], nil
}

func (t *TPM) writeState(tpm transport.TPM, state byte) error {
	pub, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(t.stateIndex)}.Execute(tpm)
	if errors.Is(err, tpm2.TPMRCHandle) {
		_, err = tpm2.NVDefineSpace{
			AuthHandle: ownerAuth,
			PublicInfo: tpm2.New2B(stateNVPublic(t.stateIndex)),
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("define state index 0x%08x err: %w", t.stateIndex, err)
		}
		pub, err = tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(t.stateIndex)}.Execute(tpm)
	}
	if err != nil {
		return fmt.Errorf("read state index public err: %w", err)
	}
	_, err = tpm2.NVWrite{
		AuthHandle: ownerAuth,
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.stateIndex), Name: pub.NVName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: []byte{state}},
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("write state err: %w", err)
	}
	return nil
}

// Reset invalidates every credential: it disables key handles created by
// versions without a device key, replaces the device key and removes the
// PIN (and with it the UV key used for hmac-secret).
func (t *TPM) Reset() error {
	return t.withTPM(func(tpm transport.TPM) error {
		// Disable legacy key handles first, so an interrupted reset
		// doesn't leave them usable.
		if err := t.writeState(tpm, stateLegacyDisabled); err != nil {
			return err
		}
		t.legacyDisabled = true

		_, err := tpm2.EvictControl{
			Auth:             ownerAuth,
			ObjectHandle:     tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.deviceKeyHandle), Name: t.deviceKeyName},
			PersistentHandle: tpm2.TPMIDHPersistent(t.deviceKeyHandle),
		}.Execute(tpm)
		if err != nil && !errors.Is(err, tpm2.TPMRCHandle) {
			return fmt.Errorf("evict device key err: %w", err)
		}
		if err := t.createDeviceKey(tpm); err != nil {
			return err
		}

		name, exists, _, err := t.pinIndex(tpm)
		if err != nil {
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
		return nil
	})
}
