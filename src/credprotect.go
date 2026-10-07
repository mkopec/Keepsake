package main

import (
	"github.com/mkopec/keepsake/src/ctap2"
)

// credProtect (CTAP 2.1 section 12.1) lets a relying party restrict when a
// credential can be used:
//
//  1. userVerificationOptional: always (the default)
//  2. userVerificationOptionalWithCredentialIDList: a discoverable
//     credential isn't discovered without user verification, only used when
//     the platform names it in the allowList
//  3. userVerificationRequired: only with user verification. Keepsake binds
//     the credential key to the PIN in the TPM, so even software that uses
//     the TPM directly can't sign with it without the PIN.

// credProtectCreate returns the credProtect level requested by a
// MakeCredential request, or 0 if it wasn't requested.
func credProtectCreate(extensions ctap2.Extensions) (int, error) {
	raw, ok := extensions[ctap2.ExtCredProtect]
	if !ok {
		return 0, nil
	}
	var level uint
	if err := ctap2.Unmarshal(raw, &level); err != nil {
		return 0, err
	}
	if level < 1 || level > 3 {
		return 0, ctap2.ErrInvalidParameter
	}
	return int(level), nil
}

// uvPinHash returns the PIN hash credentials bound to the PIN need, if the
// request is user verified.
func (s *server) uvPinHash(uv bool) []byte {
	if !uv {
		return nil
	}
	return s.pin.pinHash
}
