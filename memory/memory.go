package memory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/psanford/tpm-fido/tpm"
	"golang.org/x/crypto/chacha20poly1305"
)

type Mem struct {
	masterPrivateKey []byte
	signCounter      uint32
	pinHash          []byte
	pinRetries       int
	storeVersion     uint64
}

func New() (*Mem, error) {
	return &Mem{
		masterPrivateKey: mustRand(chacha20poly1305.KeySize),
	}, nil
}

func (m *Mem) Counter() (uint32, error) {
	m.signCounter++
	return m.signCounter, nil
}

// Key handles start with a flags byte, which is authenticated with the
// wrapped key: flagDiscoverable and the credProtect level in the next two
// bits.
const (
	flagDiscoverable = 0x01
	credProtectShift = 1
	credProtectBits  = 0x06
)

// RegisterKey creates a new key. hmac-secret is enabled for every key, so
// opts.HMACSecret is ignored. Level 3 credProtect is enforced in software.
func (m *Mem) RegisterKey(applicationParam []byte, opts tpm.KeyOptions) ([]byte, *big.Int, *big.Int, error) {
	if opts.CredProtect == 3 && m.pinHash == nil {
		return nil, nil, nil, tpm.ErrNoPIN
	}
	curve := elliptic.P256()

	childPrivateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("gen key err: %w", err)
	}

	metadata := []byte("fido_wrapping_key")
	metadata = append(metadata, applicationParam...)
	h := sha256.New()
	h.Write(metadata)
	sum := h.Sum(nil)

	aead, err := chacha20poly1305.NewX(m.masterPrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("chacha NewX err: %w", err)
	}

	var flags byte
	if opts.Discoverable {
		flags |= flagDiscoverable
	}
	if opts.CredProtect > 1 {
		flags |= byte(opts.CredProtect) << credProtectShift
	}

	nonce := mustRand(chacha20poly1305.NonceSizeX)
	encryptedChildPrivateKey := aead.Seal(nil, nonce, childPrivateKey, append(sum, flags))

	keyHandle := make([]byte, 0, 1+len(nonce)+len(encryptedChildPrivateKey))
	keyHandle = append(keyHandle, flags)
	keyHandle = append(keyHandle, nonce...)
	keyHandle = append(keyHandle, encryptedChildPrivateKey...)

	if len(keyHandle) > 255 {
		panic("keyHandle is too big")
	}

	return keyHandle, x, y, nil
}

func (m *Mem) CheckKey(keyHandle, applicationParam []byte) error {
	_, err := m.unwrap(keyHandle, applicationParam)
	return err
}

func (m *Mem) KeyInfo(keyHandle []byte) (tpm.KeyOptions, error) {
	if len(keyHandle) == 0 {
		return tpm.KeyOptions{}, fmt.Errorf("empty key handle")
	}
	opts := tpm.KeyOptions{
		HMACSecret:   true,
		Discoverable: keyHandle[0]&flagDiscoverable != 0,
		CredProtect:  int(keyHandle[0]&credProtectBits) >> credProtectShift,
	}
	if opts.CredProtect == 0 {
		opts.CredProtect = 1
	}
	return opts, nil
}

func (m *Mem) SignASN1(keyHandle, applicationParam, digest, uvPinHash []byte) ([]byte, error) {
	childPrivateKey, err := m.unwrap(keyHandle, applicationParam)
	if err != nil {
		return nil, err
	}
	if opts, _ := m.KeyInfo(keyHandle); opts.CredProtect == 3 &&
		(m.pinHash == nil || subtle.ConstantTimeCompare(m.pinHash, uvPinHash) != 1) {
		return nil, tpm.ErrPINRequired
	}

	var ecdsaKey ecdsa.PrivateKey

	ecdsaKey.D = new(big.Int).SetBytes(childPrivateKey)
	ecdsaKey.PublicKey.Curve = elliptic.P256()
	ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y = ecdsaKey.PublicKey.Curve.ScalarBaseMult(ecdsaKey.D.Bytes())

	return ecdsa.SignASN1(rand.Reader, &ecdsaKey, digest)
}

func (m *Mem) unwrap(keyHandle, applicationParam []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(m.masterPrivateKey)
	if err != nil {
		panic(err)
	}

	if len(keyHandle) < 1+chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("incorrect size for key handle: %d smaller than nonce)", len(keyHandle))
	}
	flags := keyHandle[0]
	nonce := keyHandle[1 : 1+chacha20poly1305.NonceSizeX]
	cipherText := keyHandle[1+chacha20poly1305.NonceSizeX:]

	metadata := []byte("fido_wrapping_key")
	metadata = append(metadata, applicationParam[:]...)
	h := sha256.New()
	h.Write(metadata)
	sum := h.Sum(nil)

	childPrivateKey, err := aead.Open(nil, nonce, cipherText, append(sum, flags))
	if err != nil {
		return nil, fmt.Errorf("open child private key err: %w", err)
	}
	return childPrivateKey, nil
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}

func (m *Mem) PINSet() (bool, error) {
	return m.pinHash != nil, nil
}

func (m *Mem) SetPIN(pinHash, oldPinHash []byte, retries int) error {
	m.pinHash = append([]byte(nil), pinHash...)
	m.pinRetries = retries
	return nil
}

func (m *Mem) PINRetries() (int, error) {
	return m.pinRetries, nil
}

func (m *Mem) SetPINRetries(retries int) error {
	m.pinRetries = retries
	return nil
}

func (m *Mem) VerifyPIN(pinHash []byte) (bool, error) {
	return subtle.ConstantTimeCompare(m.pinHash, pinHash) == 1, nil
}

// HMACSecret derives the hmac-secret CredRandom from the master key. With
// uvPinHash it derives the secret used with user verification.
func (m *Mem) HMACSecret(keyHandle, rpIDHash, uvPinHash []byte) ([]byte, error) {
	label := "memory hmac-secret"
	if uvPinHash != nil {
		if subtle.ConstantTimeCompare(m.pinHash, uvPinHash) != 1 {
			return nil, fmt.Errorf("wrong PIN hash")
		}
		label = "memory hmac-secret uv"
	}
	credHash := sha256.Sum256(keyHandle)
	mac := hmac.New(sha256.New, m.masterPrivateKey)
	mac.Write([]byte(label))
	mac.Write(rpIDHash)
	mac.Write(credHash[:])
	return mac.Sum(nil), nil
}

func (m *Mem) StoreKey() ([]byte, error) {
	mac := hmac.New(sha256.New, m.masterPrivateKey)
	mac.Write([]byte("memory passkey store key"))
	return mac.Sum(nil), nil
}

// Reset replaces the master key, invalidating every credential, and
// removes the PIN.
func (m *Mem) Reset() error {
	m.masterPrivateKey = mustRand(chacha20poly1305.KeySize)
	m.pinHash = nil
	m.pinRetries = 0
	return nil
}

func (m *Mem) StoreVersion() (uint64, error) {
	return m.storeVersion, nil
}

func (m *Mem) AdvanceStoreVersion(v uint64) error {
	if v != m.storeVersion+1 {
		return fmt.Errorf("store counter is %d, can't advance it to %d", m.storeVersion, v)
	}
	m.storeVersion = v
	return nil
}
