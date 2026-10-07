package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/psanford/tpm-fido/internal/lencode"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

var (
	separator     = []byte("TPM")
	seedSizeBytes = 20
)

// DefaultCounterIndex is the NV index used for the signature counter. It is
// in the owner range (0x01000000-0x013FFFFF) of the TCG handle registry.
const DefaultCounterIndex = 0x0100F1D0

// counterOffset is added to the NV counter value. Earlier versions reported
// the seconds since 2021-01-01 as the signature counter; starting above any
// value that could have produced (until mid 2029) keeps the counter
// increasing for existing credentials.
const counterOffset = 0x10000000

// TPM_NT_COUNTER in the TPM_NT field of TPMA_NV
const nvTypeCounter tpm2.NVAttr = 0x10

// The counter is a hybrid (orderly) counter so that the TPM only writes it to
// NV on shutdown instead of on every increment. After an unclean shutdown it
// jumps forward, which is fine for a signature counter.
const counterAttrs = nvTypeCounter | tpm2.AttrAuthWrite | tpm2.AttrAuthRead |
	tpm2.AttrNoDA | tpm2.AttrOrderly

type TPM struct {
	devicePath     string
	counterIndex   tpmutil.Handle
	pinIndexHandle uint32
	mu             sync.Mutex
}

func (t *TPM) open() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM(t.devicePath)
}

func New(devicePath string, counterIndex, pinIndex uint32) (*TPM, error) {
	t := &TPM{
		devicePath:     devicePath,
		counterIndex:   tpmutil.Handle(counterIndex),
		pinIndexHandle: pinIndex,
	}

	tpm, err := t.open()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	if err := t.ensureCounter(tpm); err != nil {
		return nil, err
	}

	return t, nil
}

// ensureCounter defines the counter NV index if it doesn't exist yet.
func (t *TPM) ensureCounter(tpm io.ReadWriter) error {
	pub, err := tpm2.NVReadPublic(tpm, t.counterIndex)
	if err == nil {
		if pub.Attributes&^tpm2.AttrWritten != counterAttrs || pub.DataSize != 8 {
			return fmt.Errorf("NV index 0x%08x exists but is not a tpm-fido counter (attributes %s)", t.counterIndex, pub.Attributes)
		}
		return nil
	}

	err = tpm2.NVDefineSpace(tpm, tpm2.HandleOwner, t.counterIndex, "", "", nil, counterAttrs, 8)
	if err != nil {
		return fmt.Errorf("define counter NV index 0x%08x (requires empty owner auth) err: %w", t.counterIndex, err)
	}
	return nil
}

// Key handles created by current versions prefix the seed with a version
// byte. Their keys have noDA set: the keys have an empty authValue, so
// dictionary attack protection doesn't protect anything, and without noDA
// they can't be used while the TPM is in lockout, e.g. after wrong PIN
// guesses. Key handles with a bare 20 byte seed were created without noDA.
// The flag changes the primary key template, so it can't be changed for
// existing key handles.
const (
	keyHandleVersionNoDA = 0x01
	// like keyHandleVersionNoDA, for credentials created with the
	// hmac-secret extension
	keyHandleVersionHMACSecret = 0x02
)

type keyHandleFlags struct {
	noDA       bool
	hmacSecret bool
}

// parseSeed splits the seed field of a key handle into the HKDF seed and
// the key handle flags.
func parseSeed(field []byte) (seed []byte, flags keyHandleFlags, err error) {
	if len(field) == seedSizeBytes {
		return field, flags, nil
	}
	if len(field) == seedSizeBytes+1 {
		switch field[0] {
		case keyHandleVersionNoDA:
			return field[1:], keyHandleFlags{noDA: true}, nil
		case keyHandleVersionHMACSecret:
			return field[1:], keyHandleFlags{noDA: true, hmacSecret: true}, nil
		}
	}
	return nil, flags, fmt.Errorf("invalid key handle seed")
}

var errInvalidHandle = errors.New("invalid key handle")

// decodeKeyHandle splits a key handle into its fields.
func decodeKeyHandle(keyHandle []byte) (private, public, seed []byte, flags keyHandleFlags, err error) {
	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))

	if private, err = dec.Decode(); err != nil {
		return nil, nil, nil, flags, errInvalidHandle
	}
	if public, err = dec.Decode(); err != nil {
		return nil, nil, nil, flags, errInvalidHandle
	}
	seedField, err := dec.Decode()
	if err != nil {
		return nil, nil, nil, flags, errInvalidHandle
	}
	if _, err = dec.Decode(); err != io.EOF {
		return nil, nil, nil, flags, errInvalidHandle
	}
	if seed, flags, err = parseSeed(seedField); err != nil {
		return nil, nil, nil, flags, errInvalidHandle
	}
	return private, public, seed, flags, nil
}

func primaryKeyTmpl(seed, applicationParam []byte, noDA bool) tpm2.Public {
	info := append([]byte("tpm-fido-application-key"), applicationParam...)

	r := hkdf.New(sha256.New, seed, []byte{}, info)
	unique := tpm2.ECPoint{
		XRaw: make([]byte, 32),
		YRaw: make([]byte, 32),
	}
	if _, err := io.ReadFull(r, unique.XRaw); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, unique.YRaw); err != nil {
		panic(err)
	}

	attrs := tpm2.FlagRestricted | tpm2.FlagDecrypt |
		tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
		tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth
	if noDA {
		attrs |= tpm2.FlagNoDA
	}

	return tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: attrs,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
			Point:   unique,
		},
	}
}

// Counter increments the TPM NV counter and returns the new value.
func (t *TPM) Counter() (uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return 0, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	if err := tpm2.NVIncrement(tpm, t.counterIndex, ""); err != nil {
		return 0, fmt.Errorf("NV increment err: %w", err)
	}

	val, err := tpm2.NVReadEx(tpm, t.counterIndex, t.counterIndex, "", 8)
	if err != nil {
		return 0, fmt.Errorf("NV read err: %w", err)
	}
	if len(val) != 8 {
		return 0, fmt.Errorf("unexpected counter size %d", len(val))
	}

	return uint32(binary.BigEndian.Uint64(val) + counterOffset), nil
}

// Register a new key with the TPM for the given applicationParam.
// RegisterKey returns the KeyHandle or an error. hmacSecret enables the
// hmac-secret extension for the key.
func (t *TPM) RegisterKey(applicationParam []byte, hmacSecret bool) ([]byte, *big.Int, *big.Int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	randSeed := mustRand(seedSizeBytes)
	version := byte(keyHandleVersionNoDA)
	if hmacSecret {
		version = keyHandleVersionHMACSecret
	}
	seedField := append([]byte{version}, randSeed...)

	primaryTmpl := primaryKeyTmpl(randSeed, applicationParam, true)

	childTmpl := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagSign | tpm2.FlagNoDA,
		ECCParameters: &tpm2.ECCParams{

			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}

	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", primaryTmpl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}

	defer tpm2.FlushContext(tpm, parentHandle)

	private, public, _, _, _, err := tpm2.CreateKey(tpm, parentHandle, tpm2.PCRSelection{}, "", "", childTmpl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreateKey (child) err: %w", err)
	}

	var out bytes.Buffer
	enc := lencode.NewEncoder(&out, lencode.SeparatorOpt(separator))

	enc.Encode(private)
	enc.Encode(public)
	enc.Encode(seedField)

	keyHandle, _, err := tpm2.Load(tpm, parentHandle, "", public, private)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load child key err: %w", err)
	}

	defer tpm2.FlushContext(tpm, keyHandle)

	pub, _, _, err := tpm2.ReadPublic(tpm, keyHandle)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read public key err: %w", err)
	}

	x := new(big.Int).SetBytes(pub.ECCParameters.Point.XRaw)
	y := new(big.Int).SetBytes(pub.ECCParameters.Point.YRaw)

	return out.Bytes(), x, y, nil
}

func (t *TPM) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	private, public, seed, flags, err := decodeKeyHandle(keyHandle)
	if err != nil {
		return nil, err
	}

	srkTemplate := primaryKeyTmpl(seed, applicationParam, flags.noDA)

	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}

	defer tpm2.FlushContext(tpm, parentHandle)

	key, _, err := tpm2.Load(tpm, parentHandle, "", public, private)
	if err != nil {
		return nil, fmt.Errorf("Load err: %w", err)
	}

	defer tpm2.FlushContext(tpm, key)

	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}

	sig, err := tpm2.Sign(tpm, key, "", digest[:], nil, scheme)
	if err != nil {
		return nil, fmt.Errorf("sign err: %w", err)
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(sig.ECC.R)
		b.AddASN1BigInt(sig.ECC.S)
	})

	return b.Bytes()
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
