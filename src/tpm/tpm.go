package tpm

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	tpm2new "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

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

// Handles are the TPM NV indices and persistent handles used by keepsake.
type Handles struct {
	CounterIndex uint32
	PINIndex     uint32
	StateIndex   uint32
	DeviceKey    uint32
	// StoreCounter is the passkey store's anti-rollback counter
	StoreCounter uint32
	// SRKNameFile pins the name of the TPM's storage root key, see
	// secure.go. Empty disables pinning.
	SRKNameFile string
	// UserSecretFile holds the user secret, see user.go. It is created if
	// it doesn't exist.
	UserSecretFile string
	// BindBootState binds a newly created device key to PCR 7, so the
	// credentials can only be used after the same Secure Boot state.
	// An existing device key is unaffected until a reset.
	BindBootState bool
}

// SharedHandles are the handles development versions before per-user
// slots used for every user.
var SharedHandles = Handles{
	CounterIndex: 0x0100F1D0,
	PINIndex:     0x0100F1D1,
	StateIndex:   0x0100F1D2,
	DeviceKey:    0x8100F1D0,
}

// LeftoverSharedObjects returns the handles in SharedHandles that are in
// use, which were probably created by an earlier development version.
func (t *TPM) LeftoverSharedObjects() []uint32 {
	var used []uint32
	t.withTPM(func(tpm transport.TPM) error {
		h := SharedHandles
		for _, idx := range []uint32{h.CounterIndex, h.PINIndex, h.StateIndex} {
			if _, err := (tpm2new.NVReadPublic{NVIndex: tpm2new.TPMHandle(idx)}).Execute(tpm); err == nil {
				used = append(used, idx)
			}
		}
		if _, err := (tpm2new.ReadPublic{ObjectHandle: tpm2new.TPMHandle(h.DeviceKey)}).Execute(tpm); err == nil {
			used = append(used, h.DeviceKey)
		}
		return nil
	})
	return used
}

type TPM struct {
	devicePath      string
	counterIndex    tpmutil.Handle
	pinIndexHandle  uint32
	stateIndex      uint32
	deviceKeyHandle uint32

	mu sync.Mutex
	// protected by mu
	deviceKeyName  tpm2new.TPM2BName
	legacyDisabled bool

	// pinned SRK name, set by New
	srkName []byte
	// persistent handle of the SRK, 0 if it is created when needed
	srkHandle uint32
	// set by New
	userSecret []byte

	storeCounter uint32
	// storeCounterNew is set if New created the store counter
	storeCounterNew bool

	bindBootState  bool
	deviceKeyBound bool
	// bootStateChanged is set if the device key couldn't be used at
	// startup because PCR 7 changed
	bootStateChanged bool

	// dial replaces opening devicePath in tests
	dial func() (io.ReadWriteCloser, error)
}

func (t *TPM) open() (io.ReadWriteCloser, error) {
	if t.dial != nil {
		return t.dial()
	}
	return tpm2.OpenTPM(t.devicePath)
}

func New(devicePath string, h Handles) (*TPM, error) {
	return newTPM(devicePath, h, nil)
}

func newTPM(devicePath string, h Handles, dial func() (io.ReadWriteCloser, error)) (*TPM, error) {
	t := &TPM{
		dial:            dial,
		devicePath:      devicePath,
		counterIndex:    tpmutil.Handle(h.CounterIndex),
		pinIndexHandle:  h.PINIndex,
		stateIndex:      h.StateIndex,
		deviceKeyHandle: h.DeviceKey,
	}

	if h.UserSecretFile == "" {
		return nil, errors.New("no user secret file")
	}
	secret, err := loadUserSecret(h.UserSecretFile)
	if err != nil {
		return nil, fmt.Errorf("user secret: %w", err)
	}
	t.userSecret = secret
	t.bindBootState = h.BindBootState
	t.storeCounter = h.StoreCounter

	tpm, err := t.open()
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	if err := t.ensureCounter(tpm); err != nil {
		return nil, err
	}
	tr := transport.FromReadWriter(tpm)
	if err := t.pinSRK(tr, h.SRKNameFile); err != nil {
		return nil, err
	}
	if err := t.ensureDeviceKey(tr); err != nil {
		return nil, err
	}
	if t.storeCounter != 0 {
		if t.storeCounterNew, err = t.ensureStoreCounter(tr); err != nil {
			return nil, err
		}
	}
	state, err := t.readState(tr)
	if err != nil {
		return nil, err
	}
	t.legacyDisabled = state&stateLegacyDisabled != 0

	return t, nil
}

// ensureCounter defines the counter NV index if it doesn't exist yet.
func (t *TPM) ensureCounter(tpm io.ReadWriter) error {
	pub, err := tpm2.NVReadPublic(tpm, t.counterIndex)
	if err == nil {
		if pub.Attributes&^tpm2.AttrWritten != counterAttrs || pub.DataSize != 8 {
			return fmt.Errorf("NV index 0x%08x exists but is not a Keepsake counter (attributes %s)", t.counterIndex, pub.Attributes)
		}
		return nil
	}

	err = tpm2.NVDefineSpace(tpm, tpm2.HandleOwner, t.counterIndex, "", "", nil, counterAttrs, 8)
	if err != nil {
		return fmt.Errorf("define counter NV index 0x%08x (requires empty owner auth) err: %w", t.counterIndex, err)
	}
	return nil
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

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}

// DeviceKeyBound reports whether the device key is bound to the boot
// state, and whether the boot state changed since it was created.
func (t *TPM) DeviceKeyBound() (bound, changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.deviceKeyBound, t.bootStateChanged
}
