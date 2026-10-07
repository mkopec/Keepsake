package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// The passkey store records the value of a TPM counter, which tpm-fido
// increments whenever it saves the store, so an older copy of the store
// (e.g. from a backup) isn't accepted: it would bring back deleted, i.e.
// revoked, passkeys.
//
// Unlike the signature counter, the store counter isn't orderly: an orderly
// counter jumps forward after an unclean shutdown, which would make the
// store look rolled back. The store is saved rarely, so writing NV on every
// increment is fine.

func storeCounterNVPublic(index uint32) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMIRHNVIndex(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			NoDA:       true,
			NT:         tpm2.TPMNTCounter,
		},
		DataSize: 8,
	}
}

func (t *TPM) storeCounterName(tpm transport.TPM) (tpm2.TPM2BName, bool, error) {
	rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(t.storeCounter)}.Execute(tpm)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return tpm2.TPM2BName{}, false, nil
	}
	if err != nil {
		return tpm2.TPM2BName{}, false, fmt.Errorf("read store counter public err: %w", err)
	}
	pub, err := rsp.NVPublic.Contents()
	if err != nil {
		return tpm2.TPM2BName{}, false, err
	}
	want := storeCounterNVPublic(t.storeCounter)
	attrs := pub.Attributes
	written := attrs.Written
	attrs.Written = false
	if attrs != want.Attributes || pub.DataSize != want.DataSize {
		return tpm2.TPM2BName{}, false, fmt.Errorf("NV index 0x%08x exists but is not a tpm-fido store counter", t.storeCounter)
	}
	return rsp.NVName, written, nil
}

// ensureStoreCounter defines and initializes the store counter. It reports
// whether it created it.
func (t *TPM) ensureStoreCounter(tpm transport.TPM) (bool, error) {
	_, written, err := t.storeCounterName(tpm)
	if err != nil {
		return false, err
	}
	if written {
		return false, nil
	}
	_, err = tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(t.storeCounter)}.Execute(tpm)
	if errors.Is(err, tpm2.TPMRCHandle) {
		_, err = tpm2.NVDefineSpace{
			AuthHandle: ownerAuth,
			PublicInfo: tpm2.New2B(storeCounterNVPublic(t.storeCounter)),
		}.Execute(tpm)
		if err != nil {
			return false, fmt.Errorf("define store counter 0x%08x err: %w", t.storeCounter, err)
		}
	}
	// A counter's first value is the TPM's highest counter value, so it
	// is incremented once to have a known value.
	return true, t.incrementStoreCounter(tpm)
}

func (t *TPM) incrementStoreCounter(tpm transport.TPM) error {
	rsp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(t.storeCounter)}.Execute(tpm)
	if err != nil {
		return err
	}
	_, err = tpm2.NVIncrement{
		AuthHandle: ownerAuth,
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.storeCounter), Name: rsp.NVName},
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("increment store counter err: %w", err)
	}
	return nil
}

// StoreVersion returns the store counter.
func (t *TPM) StoreVersion() (uint64, error) {
	var v uint64
	err := t.withTPM(func(tpm transport.TPM) error {
		name, _, err := t.storeCounterName(tpm)
		if err != nil {
			return err
		}
		rsp, err := tpm2.NVRead{
			AuthHandle: ownerAuth,
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(t.storeCounter), Name: name},
			Size:       8,
		}.Execute(tpm)
		if err != nil {
			return fmt.Errorf("read store counter err: %w", err)
		}
		v = binary.BigEndian.Uint64(rsp.Data.Buffer)
		return nil
	})
	return v, err
}

// AdvanceStoreVersion increments the store counter, which must be
// v-1, to v.
func (t *TPM) AdvanceStoreVersion(v uint64) error {
	cur, err := t.StoreVersion()
	if err != nil {
		return err
	}
	if cur+1 != v {
		return fmt.Errorf("store counter is %d, can't advance it to %d", cur, v)
	}
	return t.withTPM(t.incrementStoreCounter)
}

// StoreCounterNew reports whether the store counter was created at startup,
// i.e. this is the first start of a version with store versioning.
func (t *TPM) StoreCounterNew() bool {
	return t.storeCounterNew
}
