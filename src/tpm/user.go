package tpm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Every member of the tss group can use the TPM directly, so on a machine
// with several Keepsake users each user's TPM objects must be useless to the
// others. Each user has
//
//   - their own handles, derived from a slot number (by default the UID),
//     so users don't share a device key, PIN or counter, and
//   - a user secret, a random value in a file in their home directory. The
//     device key's authorization value and the PIN's authorization value in
//     the TPM are derived from it.
//
// Every credential, the hmac-secret secrets and the passkey store key
// depend on the device key, so another user who can't read the user secret
// can't use any of them, and can't even start guessing the PIN.
//
// Other users can still delete the objects (the owner hierarchy has an
// empty authorization value), which loses the credentials but doesn't give
// access to them. Legacy key handles, whose key only depends on the
// credential ID, aren't protected.

// UserSecretSize is the size of the user secret.
const UserSecretSize = 32

// Handle layout: each slot has three NV indices and one persistent handle,
// inside the owner ranges of the TCG handle registry.
const (
	nvSlotBase         = 0x01300000
	persistentSlotBase = 0x81300000
	// MaxSlot is the largest slot number.
	MaxSlot = 0xFFFF
)

// HandlesForSlot returns the handles of a slot.
func HandlesForSlot(slot int) Handles {
	return Handles{
		CounterIndex: nvSlotBase + uint32(slot)*4,
		PINIndex:     nvSlotBase + uint32(slot)*4 + 1,
		StateIndex:   nvSlotBase + uint32(slot)*4 + 2,
		StoreCounter: nvSlotBase + uint32(slot)*4 + 3,
		DeviceKey:    persistentSlotBase + uint32(slot),
	}
}

// loadUserSecret reads the user secret, creating it if path doesn't exist.
func loadUserSecret(path string) ([]byte, error) {
	secret, err := os.ReadFile(path)
	if err == nil {
		if len(secret) != UserSecretSize {
			return nil, fmt.Errorf("user secret %s has the wrong size", path)
		}
		return secret, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	secret = make([]byte, UserSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// O_EXCL: don't overwrite a secret created concurrently
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(secret); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return secret, f.Close()
}

// derive returns an authorization value derived from the user secret.
//
// It is hex encoded so it never contains a zero byte: go-tpm (v0.9.8)
// truncates HMAC session authorization values at their first zero byte
// instead of only removing trailing zeros, so a value with an embedded zero
// can't be used with an HMAC session. 16 bytes of HMAC output hex encode to
// 32 bytes, the largest authorization value for SHA-256 objects.
func (t *TPM) derive(label string, data []byte) []byte {
	mac := hmac.New(sha256.New, t.userSecret)
	mac.Write([]byte(label))
	mac.Write(data)
	return []byte(hex.EncodeToString(mac.Sum(nil)[:16]))
}

// deviceKeyAuth is the device key's authorization value.
func (t *TPM) deviceKeyAuth() []byte {
	return t.derive("tpm-fido device key auth", nil)
}

// pinAuth is the authorization value of the PIN index and the UV key for a
// PIN hash. nil stays nil.
func (t *TPM) pinAuth(pinHash []byte) []byte {
	if pinHash == nil {
		return nil
	}
	return t.derive("tpm-fido PIN auth", pinHash)
}

// checkDeviceKeyOwner fails if the device key at our handle can't be used
// with our user secret: it belongs to another user whose slot collides, or
// the user secret file was replaced.
func (t *TPM) checkDeviceKeyOwner(tpm transport.TPM) error {
	_, err := t.deviceHMAC(tpm, []byte("tpm-fido owner check"), false)
	if errors.Is(err, ErrBootStateChanged) {
		// keep running: a reset (which doesn't use the device key)
		// must remain possible
		t.bootStateChanged = true
		return nil
	}
	if errors.Is(err, tpm2.TPMRCAuthFail) || errors.Is(err, tpm2.TPMRCBadAuth) {
		return fmt.Errorf("the device key at persistent handle 0x%08x doesn't belong to this user secret: "+
			"either another user uses the same slot (choose another with -slot), or the user secret file was "+
			"replaced, which makes all credentials unusable", t.deviceKeyHandle)
	}
	return err
}
