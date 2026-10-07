package ctap2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// authenticatorClientPIN subcommands (section 5.5)
const (
	PINGetRetries      = 0x01
	PINGetKeyAgreement = 0x02
	PINSetPIN          = 0x03
	PINChangePIN       = 0x04
	PINGetPINToken     = 0x05

	// COSE algorithm identifier advertised for the key agreement key
	AlgECDHESHKDF256 = -25
)

type ClientPINReq struct {
	PinProtocol  uint     `cbor:"1,keyasint"`
	SubCommand   uint     `cbor:"2,keyasint"`
	KeyAgreement *COSEKey `cbor:"3,keyasint"`
	PinAuth      []byte   `cbor:"4,keyasint"`
	NewPinEnc    []byte   `cbor:"5,keyasint"`
	PinHashEnc   []byte   `cbor:"6,keyasint"`
}

type ClientPINResp struct {
	KeyAgreement *COSEKey `cbor:"1,keyasint,omitempty"`
	PinToken     []byte   `cbor:"2,keyasint,omitempty"`
	Retries      *int     `cbor:"3,keyasint,omitempty"`
}

// COSEKey is an EC2 COSE_Key.
type COSEKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// KeyAgreementCOSEKey encodes the authenticator's key agreement public key.
func KeyAgreementCOSEKey(pub *ecdh.PublicKey) *COSEKey {
	b := pub.Bytes() // 0x04 || x || y
	return &COSEKey{
		Kty: 2,
		Alg: AlgECDHESHKDF256,
		Crv: 1,
		X:   b[1:33],
		Y:   b[33:65],
	}
}

// ECDHPublicKey decodes a platform key agreement key. It fails if the point
// isn't on the P-256 curve.
func (k *COSEKey) ECDHPublicKey() (*ecdh.PublicKey, error) {
	if k.Kty != 2 || k.Crv != 1 || len(k.X) != 32 || len(k.Y) != 32 {
		return nil, ErrInvalidParameter
	}
	b := append([]byte{0x04}, k.X...)
	b = append(b, k.Y...)
	pub, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return nil, ErrInvalidParameter
	}
	return pub, nil
}

// PINProtocol is a PIN/UV auth protocol (CTAP 2.1 section 6.5).
type PINProtocol interface {
	Version() uint
	// SharedSecret derives the shared secret from the ECDH x-coordinate.
	SharedSecret(z []byte) []byte
	Encrypt(key, plaintext []byte) []byte
	// Decrypt returns ErrInvalidParameter if ciphertext has the wrong size.
	Decrypt(key, ciphertext []byte) ([]byte, error)
	// Authenticate computes a MAC over msg. key is either a shared secret
	// or a pinToken.
	Authenticate(key, msg []byte) []byte
}

// LookupPINProtocol returns the PIN protocol with the given version number,
// or nil if it isn't supported.
func LookupPINProtocol(version uint) PINProtocol {
	switch version {
	case 1:
		return pinProtocolV1{}
	case 2:
		return pinProtocolV2{}
	}
	return nil
}

// VerifyPINAuth checks a MAC produced by Authenticate.
func VerifyPINAuth(p PINProtocol, key, msg, mac []byte) bool {
	return hmac.Equal(p.Authenticate(key, msg), mac)
}

type pinProtocolV1 struct{}

func (pinProtocolV1) Version() uint { return 1 }

func (pinProtocolV1) SharedSecret(z []byte) []byte {
	h := sha256.Sum256(z)
	return h[:]
}

func (pinProtocolV1) Encrypt(key, plaintext []byte) []byte {
	return cbcEncrypt(key, make([]byte, aes.BlockSize), plaintext)
}

func (pinProtocolV1) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrInvalidParameter
	}
	return cbcDecrypt(key, make([]byte, aes.BlockSize), ciphertext), nil
}

func (pinProtocolV1) Authenticate(key, msg []byte) []byte {
	return hmacSHA256(key, msg)[:16]
}

type pinProtocolV2 struct{}

func (pinProtocolV2) Version() uint { return 2 }

// SharedSecret returns the HMAC key followed by the AES key.
func (pinProtocolV2) SharedSecret(z []byte) []byte {
	salt := make([]byte, 32)
	out := make([]byte, 64)
	io.ReadFull(hkdf.New(sha256.New, z, salt, []byte("CTAP2 HMAC key")), out[:32])
	io.ReadFull(hkdf.New(sha256.New, z, salt, []byte("CTAP2 AES key")), out[32:])
	return out
}

func (pinProtocolV2) Encrypt(key, plaintext []byte) []byte {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}
	return append(iv, cbcEncrypt(v2AESKey(key), iv, plaintext)...)
}

func (pinProtocolV2) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2*aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrInvalidParameter
	}
	iv, ct := ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:]
	return cbcDecrypt(v2AESKey(key), iv, ct), nil
}

func (pinProtocolV2) Authenticate(key, msg []byte) []byte {
	if len(key) > 32 {
		key = key[:32] // shared secret: use the HMAC key part
	}
	return hmacSHA256(key, msg)
}

func v2AESKey(key []byte) []byte {
	if len(key) > 32 {
		return key[32:]
	}
	return key
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func cbcEncrypt(key, iv, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out
}

func cbcDecrypt(key, iv, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out
}

// ExtHMACSecret is the identifier of the hmac-secret extension.
const ExtHMACSecret = "hmac-secret"

// HMACSecretInput is the hmac-secret extension input of GetAssertion.
type HMACSecretInput struct {
	KeyAgreement *COSEKey `cbor:"1,keyasint"`
	SaltEnc      []byte   `cbor:"2,keyasint"`
	SaltAuth     []byte   `cbor:"3,keyasint"`
	// added in CTAP 2.1; defaults to 1
	PinUvAuthProtocol uint `cbor:"4,keyasint"`
}
