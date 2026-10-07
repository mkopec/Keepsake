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
//   - Without user verification, the device key. Anyone who can use the TPM
//     can use it, so they can compute these secrets; evicting it
//     (authenticatorReset) destroys them.
//   - With user verification, the UV key: an ordinary keyed hash key whose
//     authValue is the PIN hash, stored in the PIN index. Without the PIN,
//     the secrets derived with it can't be computed even with direct access
//     to the TPM, and guessing the PIN counts towards the TPM's dictionary
//     attack lockout.
func hmacKeyTemplate(noDA bool) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			NoDA:                noDA,
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
	return parentAuth(srk)
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

// createUVKey creates a UV key. The PIN hash is its first parameter, which
// is encrypted.
func createUVKey(sec *secure, pinHash []byte) ([]byte, error) {
	rsp, err := tpm2.Create{
		ParentHandle: srkParent(sec.srk),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: pinHash},
			},
		},
		InPublic: tpm2.New2B(hmacKeyTemplate(false)),
	}.Execute(sec.tpm, sec.encrypt(encryptIn))
	if err != nil {
		return nil, fmt.Errorf("create UV key err: %w", err)
	}
	return encodeUVKeyBlob(rsp.OutPrivate, rsp.OutPublic.Bytes())
}

func loadUVKey(sec *secure, blob []byte) (*tpm2.LoadResponse, error) {
	private, public, err := decodeUVKeyBlob(blob)
	if err != nil {
		return nil, err
	}
	rsp, err := tpm2.Load{
		ParentHandle: srkParent(sec.srk),
		InPrivate:    private,
		InPublic:     public,
	}.Execute(sec.tpm)
	if err != nil {
		return nil, fmt.Errorf("load UV key err: %w", err)
	}
	return rsp, nil
}

// changeUVKeyAuth re-wraps the UV key with a new PIN hash, keeping the key
// itself (and so the secrets derived with it).
func changeUVKeyAuth(sec *secure, blob, oldPinHash, newPinHash []byte) ([]byte, error) {
	key, err := loadUVKey(sec, blob)
	if err != nil {
		return nil, err
	}
	defer flush(sec.tpm, key.ObjectHandle)

	// the new PIN hash is the first parameter, encrypted
	rsp, err := tpm2.ObjectChangeAuth{
		ObjectHandle: tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: sec.auth(oldPinHash, encryptIn)},
		ParentHandle: tpm2.NamedHandle{Handle: sec.srk.ObjectHandle, Name: sec.srk.Name},
		NewAuth:      tpm2.TPM2BAuth{Buffer: newPinHash},
	}.Execute(sec.tpm)
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
	flags, err := keyHandleInfo(keyHandle)
	if err != nil {
		return nil, err
	}
	if flags.legacy || !flags.HMACSecret {
		return nil, ErrHMACSecretNotEnabled
	}

	credHash := sha256.Sum256(keyHandle)
	msg := append([]byte("tpm-fido hmac-secret"), rpIDHash...)
	msg = append(msg, credHash[:]...)

	var out []byte
	err = t.withTPM(func(tpm transport.TPM) error {
		if uvPinHash == nil {
			var err error
			out, err = t.deviceHMAC(tpm, msg, true)
			return err
		}

		sec, err := t.secure(tpm)
		if err != nil {
			return err
		}
		defer sec.close()
		uvKey, err := t.loadUVKeyFromIndex(tpm, sec)
		if err != nil {
			return err
		}
		defer flush(tpm, uvKey.ObjectHandle)
		// the HMAC output is the first response parameter, encrypted
		key := tpm2.AuthHandle{Handle: uvKey.ObjectHandle, Name: uvKey.Name, Auth: sec.auth(uvPinHash, encryptOut)}

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

// loadUVKeyFromIndex loads the UV key stored in the PIN index.
func (t *TPM) loadUVKeyFromIndex(tpm transport.TPM, sec *secure) (*tpm2.LoadResponse, error) {
	name, err := t.pinIndexWritten(tpm)
	if err != nil {
		return nil, err
	}
	blob, err := t.readUVKeyBlob(tpm, name)
	if err != nil {
		return nil, err
	}
	return loadUVKey(sec, blob)
}

// uvKeyName returns the name of the UV key, or ErrNoPIN if no PIN is set.
func (t *TPM) uvKeyName(tpm transport.TPM) (tpm2.TPM2BName, error) {
	name, _, written, err := t.pinIndex(tpm)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	if !written {
		return tpm2.TPM2BName{}, ErrNoPIN
	}
	blob, err := t.readUVKeyBlob(tpm, name)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	_, public, err := decodeUVKeyBlob(blob)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	pub, err := public.Contents()
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	n, err := tpm2.ObjectName(pub)
	if err != nil {
		return tpm2.TPM2BName{}, err
	}
	return *n, nil
}
