package tpm

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ErrHMACSecretNotEnabled is returned by HMACSecret for credentials that
// weren't created with the hmac-secret extension.
var ErrHMACSecretNotEnabled = errors.New("hmac-secret not enabled for credential")

// hmac-secret derives two secrets per credential (CredRandomWithoutUV and
// CredRandomWithUV in CTAP 2.1) by HMACing the credential with one of two
// TPM keys:
//
//   - The no-UV key is a keyed hash primary key in the owner hierarchy. It is
//     derived from the owner seed, so it never leaves the TPM and is lost
//     when the TPM is cleared, but anyone who can use the TPM can recreate
//     it.
//   - The UV key is an ordinary keyed hash key whose authValue is the PIN
//     hash, stored in the PIN index. Without the PIN, the secrets derived
//     with it can't be computed even with direct access to the TPM, and
//     guessing the PIN counts towards the TPM's dictionary attack lockout.
func hmacKeyTemplate(primary bool) tpm2.TPMTPublic {
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			// The primary key has an empty authValue. The UV key is
			// protected by the PIN, so it must count towards lockout.
			NoDA: primary,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256}),
				},
			}),
	}
	if primary {
		// The unique field makes the derived key specific to tpm-fido.
		label := sha256.Sum256([]byte("tpm-fido hmac-secret"))
		pub.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: label[:]})
	}
	return pub
}

func createSRK(tpm transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: ownerAuth,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create SRK err: %w", err)
	}
	return rsp, nil
}

func flush(tpm transport.TPM, h tpm2.TPMHandle) {
	tpm2.FlushContext{FlushHandle: h}.Execute(tpm)
}

func srkParent(srk *tpm2.CreatePrimaryResponse) tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name, Auth: tpm2.PasswordAuth(nil)}
}

// A UV key blob is the key's private area followed by its public area, each
// prefixed with a big endian uint16 length.
func encodeUVKeyBlob(private tpm2.TPM2BPrivate, public []byte) ([]byte, error) {
	var blob []byte
	blob = binary.BigEndian.AppendUint16(blob, uint16(len(private.Buffer)))
	blob = append(blob, private.Buffer...)
	blob = binary.BigEndian.AppendUint16(blob, uint16(len(public)))
	blob = append(blob, public...)
	if len(blob) > maxUVKeyBlobSize {
		return nil, fmt.Errorf("UV key blob too large: %d bytes", len(blob))
	}
	return blob, nil
}

func decodeUVKeyBlob(blob []byte) (tpm2.TPM2BPrivate, tpm2.TPM2BPublic, error) {
	next := func() ([]byte, bool) {
		if len(blob) < 2 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(blob))
		if len(blob) < 2+n {
			return nil, false
		}
		field := blob[2 : 2+n]
		blob = blob[2+n:]
		return field, true
	}
	private, ok1 := next()
	public, ok2 := next()
	if !ok1 || !ok2 || len(blob) != 0 {
		return tpm2.TPM2BPrivate{}, tpm2.TPM2BPublic{}, errors.New("invalid UV key blob")
	}
	return tpm2.TPM2BPrivate{Buffer: private}, tpm2.BytesAs2B[tpm2.TPMTPublic](public), nil
}

func createUVKey(tpm transport.TPM, srk *tpm2.CreatePrimaryResponse, pinHash []byte) ([]byte, error) {
	rsp, err := tpm2.Create{
		ParentHandle: srkParent(srk),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: pinHash},
			},
		},
		InPublic: tpm2.New2B(hmacKeyTemplate(false)),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create UV key err: %w", err)
	}
	return encodeUVKeyBlob(rsp.OutPrivate, rsp.OutPublic.Bytes())
}

func loadUVKey(tpm transport.TPM, srk *tpm2.CreatePrimaryResponse, blob []byte) (*tpm2.LoadResponse, error) {
	private, public, err := decodeUVKeyBlob(blob)
	if err != nil {
		return nil, err
	}
	rsp, err := tpm2.Load{
		ParentHandle: srkParent(srk),
		InPrivate:    private,
		InPublic:     public,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("load UV key err: %w", err)
	}
	return rsp, nil
}

// changeUVKeyAuth re-wraps the UV key with a new PIN hash, keeping the key
// itself (and so the secrets derived with it).
func changeUVKeyAuth(tpm transport.TPM, srk *tpm2.CreatePrimaryResponse, blob, oldPinHash, newPinHash []byte) ([]byte, error) {
	key, err := loadUVKey(tpm, srk, blob)
	if err != nil {
		return nil, err
	}
	defer flush(tpm, key.ObjectHandle)

	rsp, err := tpm2.ObjectChangeAuth{
		ObjectHandle: tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: tpm2.PasswordAuth(oldPinHash)},
		ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
		NewAuth:      tpm2.TPM2BAuth{Buffer: newPinHash},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("change UV key auth err: %w", err)
	}

	_, public, _ := decodeUVKeyBlob(blob)
	return encodeUVKeyBlob(rsp.OutPrivate, public.Bytes())
}

// HMACSecret returns the hmac-secret CredRandom for a credential. If
// uvPinHash is nil it returns the secret used without user verification,
// otherwise the one used with user verification, which requires the PIN
// hash. It returns ErrHMACSecretNotEnabled if the credential wasn't created
// with hmac-secret, and ErrLockout if the TPM refuses the PIN hash because
// it is in dictionary attack lockout.
func (t *TPM) HMACSecret(keyHandle, rpIDHash, uvPinHash []byte) ([]byte, error) {
	_, _, _, flags, err := decodeKeyHandle(keyHandle)
	if err != nil {
		return nil, err
	}
	if !flags.hmacSecret {
		return nil, ErrHMACSecretNotEnabled
	}

	credHash := sha256.Sum256(keyHandle)
	msg := append([]byte("tpm-fido hmac-secret"), rpIDHash...)
	msg = append(msg, credHash[:]...)

	var out []byte
	err = t.withTPM(func(tpm transport.TPM) error {
		var key tpm2.AuthHandle
		if uvPinHash == nil {
			rsp, err := tpm2.CreatePrimary{
				PrimaryHandle: ownerAuth,
				InPublic:      tpm2.New2B(hmacKeyTemplate(true)),
			}.Execute(tpm)
			if err != nil {
				return fmt.Errorf("create hmac-secret key err: %w", err)
			}
			defer flush(tpm, rsp.ObjectHandle)
			key = tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(nil)}
		} else {
			name, err := t.pinIndexWritten(tpm)
			if err != nil {
				return err
			}
			blob, err := t.readUVKeyBlob(tpm, name)
			if err != nil {
				return err
			}
			srk, err := createSRK(tpm)
			if err != nil {
				return err
			}
			defer flush(tpm, srk.ObjectHandle)
			rsp, err := loadUVKey(tpm, srk, blob)
			if err != nil {
				return err
			}
			defer flush(tpm, rsp.ObjectHandle)
			key = tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: tpm2.PasswordAuth(uvPinHash)}
		}

		rsp, err := tpm2.Hmac{
			Handle:  key,
			Buffer:  tpm2.TPM2BMaxBuffer{Buffer: msg},
			HashAlg: tpm2.TPMAlgSHA256,
		}.Execute(tpm)
		if ok, cerr := classifyAuthErr(err); cerr != nil {
			return fmt.Errorf("hmac-secret HMAC err: %w", cerr)
		} else if !ok {
			return errors.New("hmac-secret HMAC err: wrong PIN hash")
		}
		out = rsp.OutHMAC.Buffer
		return nil
	})
	return out, err
}
