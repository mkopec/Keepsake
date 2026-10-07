package tpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/mkopec/keepsake/src/internal/lencode"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

var (
	separator     = []byte("TPM")
	seedSizeBytes = 20
)

// A key handle (credential ID) is the credential key's wrapped private
// area, its public area and a seed field, lencode encoded. The credential
// key is a child of a primary key derived from the seed field and the
// relying party, so a key handle only loads on the TPM that created it, for
// the relying party it was created for.
//
// Key handles created by current versions prefix the 20 byte seed with a
// version byte: the high nibble is the format and the low nibble holds
// flags. The primary key is derived from an HMAC of the version byte and
// the seed computed with the device key, so
//
//   - evicting the device key (authenticatorReset) invalidates the
//     credential, and
//   - the flags can't be changed: a key handle with modified flags doesn't
//     load. (Format 0x10, used by unreleased versions, didn't authenticate
//     the flags and is no longer accepted.)
//
// Key handles with a bare 20 byte seed were created by versions without a
// device key ("legacy"); their primary key is derived from the seed alone.
const (
	// Format 0x30 credential keys have an authorization value derived
	// with the device key, sent to the TPM encrypted and only used in
	// HMAC sessions. Without it, someone who recorded the bus of a
	// discrete TPM (which shows the primary key template) could use a
	// credential key without Keepsake, even after a reset. Format 0x20
	// keys don't have one; they are still accepted.
	keyHandleFormat     = 0x30
	keyHandleFormatV2   = 0x20
	keyHandleFormatMask = 0xF0

	// the credential was created with the hmac-secret extension
	keyHandleFlagHMACSecret = 0x01
	// the credential is discoverable (a passkey)
	keyHandleFlagDiscoverable = 0x02
	// credProtect level 2: userVerificationOptionalWithCredentialIDList
	keyHandleFlagCredProtectList = 0x04
	// credProtect level 3: userVerificationRequired. The credential key
	// can only be used with a policy session that proves knowledge of the
	// PIN.
	keyHandleFlagCredProtectUV = 0x08
)

// ErrPINRequired is returned when a credential bound to the PIN is used
// without the PIN hash.
var ErrPINRequired = errors.New("credential requires user verification")

// ErrNoPIN is returned when creating a credential bound to the PIN while no
// PIN is set.
var ErrNoPIN = errors.New("no PIN set")

// KeyOptions are the properties of a new credential.
type KeyOptions struct {
	HMACSecret   bool
	Discoverable bool
	// CredProtect is the credProtect level: 0 or 1 (no protection),
	// 2 or 3. Level 3 binds the credential key to the PIN.
	CredProtect int
}

type keyHandleFlags struct {
	legacy bool
	// the credential key has an authorization value (format 0x30)
	credAuth bool
	format   byte
	KeyOptions
}

func (f keyHandleFlags) versionByte() byte {
	b := f.format
	if b == 0 {
		b = keyHandleFormat
	}
	if f.HMACSecret {
		b |= keyHandleFlagHMACSecret
	}
	if f.Discoverable {
		b |= keyHandleFlagDiscoverable
	}
	switch f.CredProtect {
	case 2:
		b |= keyHandleFlagCredProtectList
	case 3:
		b |= keyHandleFlagCredProtectUV
	}
	return b
}

// parseSeed splits the seed field of a key handle into the seed and the key
// handle flags.
func parseSeed(field []byte) (seed []byte, flags keyHandleFlags, err error) {
	if len(field) == seedSizeBytes {
		return field, keyHandleFlags{legacy: true}, nil
	}
	if len(field) == seedSizeBytes+1 && (field[0]&keyHandleFormatMask == keyHandleFormat || field[0]&keyHandleFormatMask == keyHandleFormatV2) {
		v := field[0]
		flags.format = v & keyHandleFormatMask
		flags.credAuth = flags.format == keyHandleFormat
		flags.HMACSecret = v&keyHandleFlagHMACSecret != 0
		flags.Discoverable = v&keyHandleFlagDiscoverable != 0
		switch v & (keyHandleFlagCredProtectList | keyHandleFlagCredProtectUV) {
		case 0:
			flags.CredProtect = 1
		case keyHandleFlagCredProtectList:
			flags.CredProtect = 2
		case keyHandleFlagCredProtectUV:
			flags.CredProtect = 3
		default:
			return nil, flags, errInvalidHandle
		}
		return field[1:], flags, nil
	}
	return nil, flags, errInvalidHandle
}

var errInvalidHandle = errors.New("invalid key handle")

// decodeKeyHandle splits a key handle into its fields.
func decodeKeyHandle(keyHandle []byte) (private, public, seedField []byte, err error) {
	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))

	if private, err = dec.Decode(); err != nil {
		return nil, nil, nil, errInvalidHandle
	}
	if public, err = dec.Decode(); err != nil {
		return nil, nil, nil, errInvalidHandle
	}
	if seedField, err = dec.Decode(); err != nil {
		return nil, nil, nil, errInvalidHandle
	}
	if _, err = dec.Decode(); err != io.EOF {
		return nil, nil, nil, errInvalidHandle
	}
	return private, public, seedField, nil
}

func keyHandleInfo(keyHandle []byte) (keyHandleFlags, error) {
	_, _, seedField, err := decodeKeyHandle(keyHandle)
	if err != nil {
		return keyHandleFlags{}, err
	}
	_, flags, err := parseSeed(seedField)
	return flags, err
}

// KeyInfo returns the properties recorded in a key handle. It doesn't check
// that the key handle is valid; the properties can't be modified in valid
// key handles.
func (t *TPM) KeyInfo(keyHandle []byte) (KeyOptions, error) {
	flags, err := keyHandleInfo(keyHandle)
	if flags.legacy {
		flags.CredProtect = 1
	}
	return flags.KeyOptions, err
}

// primaryTemplate returns the template of the primary key a credential key
// is the child of. It must stay byte for byte the same as in earlier
// versions, or their key handles stop loading.
func primaryTemplate(seed, applicationParam []byte, noDA bool) tpm2.TPMTPublic {
	info := append([]byte("tpm-fido-application-key"), applicationParam...)

	r := hkdf.New(sha256.New, seed, []byte{}, info)
	x, y := make([]byte, 32), make([]byte, 32)
	if _, err := io.ReadFull(r, x); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, y); err != nil {
		panic(err)
	}

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			Restricted:          true,
			Decrypt:             true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                noDA,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
				Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
			},
			Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: x},
			Y: tpm2.TPM2BECCParameter{Buffer: y},
		}),
	}
}

// credentialTemplate is the template of a credential key. With a policy
// digest, the key can only be used through a policy session.
// credAuth returns the authorization value of a format 0x30 credential key.
// The device key HMAC is received encrypted.
func (t *TPM) credAuth(tpm transport.TPM, seed []byte, flags keyHandleFlags) ([]byte, error) {
	msg := append([]byte("tpm-fido credential auth"), flags.versionByte())
	mac, err := t.deviceHMAC(tpm, append(msg, seed...), true)
	if err != nil {
		return nil, err
	}
	// hex: no zero bytes, see derive
	return []byte(hex.EncodeToString(mac[:16])), nil
}

func credentialTemplate(policy []byte) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        policy == nil,
			SignEncrypt:         true,
			NoDA:                true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policy},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}

// pinPolicy is the policy of credential keys bound to the PIN:
// PolicySecret with the UV key, whose authValue is the PIN hash. The UV key
// keeps its name when the PIN changes, so bound credentials survive PIN
// changes; it is destroyed when the PIN is removed (and by a reset).
func pinPolicy(uvKeyName tpm2.TPM2BName) ([]byte, error) {
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	cmd := tpm2.PolicySecret{AuthHandle: tpm2.NamedHandle{Name: uvKeyName}}
	if err := cmd.Update(calc); err != nil {
		return nil, err
	}
	return calc.Hash().Digest, nil
}

// primarySeed returns the seed of the primary key template.
func (t *TPM) primarySeed(tpm transport.TPM, seed []byte, flags keyHandleFlags) ([]byte, error) {
	if flags.legacy {
		if t.legacyDisabled {
			return nil, errors.New("key handles from before the last reset are disabled")
		}
		return seed, nil
	}
	msg := append([]byte("tpm-fido credential seed v2"), flags.versionByte())
	return t.deviceHMAC(tpm, append(msg, seed...), false)
}

func createPrimary(tpm transport.TPM, tmpl tpm2.TPMTPublic) (*tpm2.CreatePrimaryResponse, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: ownerAuth,
		InPublic:      tpm2.New2B(tmpl),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create primary err: %w", err)
	}
	return rsp, nil
}

func parentAuth(p *tpm2.CreatePrimaryResponse) tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: p.ObjectHandle, Name: p.Name, Auth: tpm2.PasswordAuth(nil)}
}

// RegisterKey creates a credential key for applicationParam (the rpIdHash)
// and returns its key handle and public key.
func (t *TPM) RegisterKey(applicationParam []byte, opts KeyOptions) ([]byte, *big.Int, *big.Int, error) {
	return t.registerKey(applicationParam, keyHandleFlags{KeyOptions: opts, credAuth: true, format: keyHandleFormat})
}

// registerKey creates a credential key; tests use it to create format 0x20
// key handles.
func (t *TPM) registerKey(applicationParam []byte, flags keyHandleFlags) ([]byte, *big.Int, *big.Int, error) {
	opts := flags.KeyOptions
	var (
		keyHandle []byte
		x, y      *big.Int
	)
	err := t.withTPM(func(tpm transport.TPM) error {
		seed := mustRand(seedSizeBytes)
		var auth []byte
		if flags.credAuth {
			var err error
			if auth, err = t.credAuth(tpm, seed, flags); err != nil {
				return err
			}
		}

		var policy []byte
		if opts.CredProtect == 3 {
			name, err := t.uvKeyName(tpm)
			if err != nil {
				return err
			}
			if policy, err = pinPolicy(name); err != nil {
				return err
			}
		}

		pSeed, err := t.primarySeed(tpm, seed, flags)
		if err != nil {
			return err
		}
		primary, err := createPrimary(tpm, primaryTemplate(pSeed, applicationParam, true))
		if err != nil {
			return err
		}
		defer flush(tpm, primary.ObjectHandle)

		// the authorization value is the first parameter, encrypted
		sec, err := t.secure(tpm)
		if err != nil {
			return err
		}
		created, err := tpm2.Create{
			ParentHandle: parentAuth(primary),
			InSensitive: tpm2.TPM2BSensitiveCreate{
				Sensitive: &tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: auth}},
			},
			InPublic: tpm2.New2B(credentialTemplate(policy)),
		}.Execute(tpm, sec.encrypt(encryptIn))
		sec.close()
		if err != nil {
			return fmt.Errorf("create credential key err: %w", err)
		}
		pub, err := created.OutPublic.Contents()
		if err != nil {
			return err
		}
		point, err := pub.Unique.ECC()
		if err != nil {
			return err
		}
		x = new(big.Int).SetBytes(point.X.Buffer)
		y = new(big.Int).SetBytes(point.Y.Buffer)

		var out bytes.Buffer
		enc := lencode.NewEncoder(&out, lencode.SeparatorOpt(separator))
		enc.Encode(created.OutPrivate.Buffer)
		enc.Encode(created.OutPublic.Bytes())
		if err := enc.Encode(append([]byte{flags.versionByte()}, seed...)); err != nil {
			return err
		}
		keyHandle = out.Bytes()
		return nil
	})
	return keyHandle, x, y, err
}

// loadCredential loads the credential key of keyHandle. The caller must
// call the returned function to flush it.
func (t *TPM) loadCredential(tpm transport.TPM, keyHandle, applicationParam []byte) (*tpm2.LoadResponse, keyHandleFlags, func(), error) {
	private, public, seedField, err := decodeKeyHandle(keyHandle)
	if err != nil {
		return nil, keyHandleFlags{}, nil, err
	}
	seed, flags, err := parseSeed(seedField)
	if err != nil {
		return nil, flags, nil, err
	}
	pSeed, err := t.primarySeed(tpm, seed, flags)
	if err != nil {
		return nil, flags, nil, err
	}
	primary, err := createPrimary(tpm, primaryTemplate(pSeed, applicationParam, !flags.legacy))
	if err != nil {
		return nil, flags, nil, err
	}
	key, err := tpm2.Load{
		ParentHandle: parentAuth(primary),
		InPrivate:    tpm2.TPM2BPrivate{Buffer: private},
		InPublic:     tpm2.BytesAs2B[tpm2.TPMTPublic](public),
	}.Execute(tpm)
	if err != nil {
		flush(tpm, primary.ObjectHandle)
		return nil, flags, nil, errInvalidHandle
	}
	return key, flags, func() {
		flush(tpm, key.ObjectHandle)
		flush(tpm, primary.ObjectHandle)
	}, nil
}

// CheckKey returns nil if keyHandle is a credential created by this TPM
// for applicationParam. It doesn't use the key.
func (t *TPM) CheckKey(keyHandle, applicationParam []byte) error {
	return t.withTPM(func(tpm transport.TPM) error {
		_, _, done, err := t.loadCredential(tpm, keyHandle, applicationParam)
		if err != nil {
			return err
		}
		done()
		return nil
	})
}

// SignASN1 signs digest with the credential key of keyHandle. Credentials
// bound to the PIN need uvPinHash, the PIN hash; it is ignored for other
// credentials.
func (t *TPM) SignASN1(keyHandle, applicationParam, digest, uvPinHash []byte) ([]byte, error) {
	uvPinHash = t.pinAuth(uvPinHash)
	var sig []byte
	err := t.withTPM(func(tpm transport.TPM) error {
		flags, err := keyHandleInfo(keyHandle)
		if err != nil {
			return err
		}
		// Satisfy the policy before loading the credential key, so that
		// no more than three objects are loaded at a time.
		var auth tpm2.Session = tpm2.PasswordAuth(nil)
		if flags.credAuth && flags.CredProtect != 3 {
			_, _, seedField, err := decodeKeyHandle(keyHandle)
			if err != nil {
				return err
			}
			seed, _, err := parseSeed(seedField)
			if err != nil {
				return err
			}
			value, err := t.credAuth(tpm, seed, flags)
			if err != nil {
				return err
			}
			// an HMAC session proves knowledge of the value without
			// sending it
			auth = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(value))
		}
		if flags.CredProtect == 3 {
			if uvPinHash == nil {
				return ErrPINRequired
			}
			policy, closeSession, err := t.pinPolicySession(tpm, uvPinHash)
			if err != nil {
				return err
			}
			defer closeSession()
			auth = policy
		}

		key, _, done, err := t.loadCredential(tpm, keyHandle, applicationParam)
		if err != nil {
			return err
		}
		defer done()
		keyAuth := tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: auth}

		rsp, err := tpm2.Sign{
			KeyHandle: keyAuth,
			Digest:    tpm2.TPM2BDigest{Buffer: digest},
			InScheme: tpm2.TPMTSigScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
			},
			Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("sign err: %w", err)
		}
		ecdsa, err := rsp.Signature.Signature.ECDSA()
		if err != nil {
			return err
		}

		var b cryptobyte.Builder
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1BigInt(new(big.Int).SetBytes(ecdsa.SignatureR.Buffer))
			b.AddASN1BigInt(new(big.Int).SetBytes(ecdsa.SignatureS.Buffer))
		})
		sig, err = b.Bytes()
		return err
	})
	return sig, err
}

// pinPolicySession starts a policy session satisfying pinPolicy. The PIN
// hash authorizes PolicySecret through a salted session, so it never
// crosses the bus. The caller must call the returned function to close the
// session.
func (t *TPM) pinPolicySession(tpm transport.TPM, pinHash []byte) (tpm2.Session, func(), error) {
	sec, err := t.secure(tpm)
	if err != nil {
		return nil, nil, err
	}
	defer sec.close()
	uvKey, err := t.loadUVKeyFromIndex(tpm, sec)
	if err != nil {
		return nil, nil, err
	}
	// The policy session keeps the result of PolicySecret after the UV
	// key is flushed.
	defer flush(tpm, uvKey.ObjectHandle)

	session, closeSession, err := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { closeSession() }

	_, err = tpm2.PolicySecret{
		AuthHandle:    tpm2.AuthHandle{Handle: uvKey.ObjectHandle, Name: uvKey.Name, Auth: sec.auth(pinHash)},
		PolicySession: session.Handle(),
	}.Execute(tpm)
	if ok, cerr := classifyAuthErr(err); cerr != nil || !ok {
		cleanup()
		if cerr == nil {
			cerr = errors.New("wrong PIN hash")
		}
		return nil, nil, fmt.Errorf("PIN policy err: %w", cerr)
	}
	return session, cleanup, nil
}
