package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// LockoutStatus describes the TPM's dictionary attack protection.
type LockoutStatus struct {
	// LockoutAuthSet reports whether the lockout hierarchy has an
	// authorization value. Without one, anyone who can use the TPM can
	// reset the failure counter (TPM2_DictionaryAttackLockReset), which
	// makes the protection against PIN guessing useless.
	LockoutAuthSet bool
	MaxAuthFail    uint32
	// seconds after which one failure is forgotten
	LockoutInterval uint32
}

// TPM_PT_PERMANENT bit
const lockoutAuthSetBit = 1 << 2

func (t *TPM) LockoutStatus() (LockoutStatus, error) {
	var st LockoutStatus
	err := t.withTPM(func(tpm transport.TPM) error {
		props := map[tpm2.TPMPT]*uint32{}
		var permanent uint32
		props[tpm2.TPMPTPermanent] = &permanent
		props[tpm2.TPMPTMaxAuthFail] = &st.MaxAuthFail
		props[tpm2.TPMPTLockoutInterval] = &st.LockoutInterval
		for prop, out := range props {
			rsp, err := tpm2.GetCapability{
				Capability:    tpm2.TPMCapTPMProperties,
				Property:      uint32(prop),
				PropertyCount: 1,
			}.Execute(tpm)
			if err != nil {
				return fmt.Errorf("get TPM property 0x%x err: %w", uint32(prop), err)
			}
			list, err := rsp.CapabilityData.Data.TPMProperties()
			if err != nil {
				return err
			}
			if len(list.TPMProperty) == 0 || list.TPMProperty[0].Property != prop {
				return fmt.Errorf("TPM property 0x%x missing", uint32(prop))
			}
			*out = list.TPMProperty[0].Value
		}
		st.LockoutAuthSet = permanent&lockoutAuthSetBit != 0
		return nil
	})
	return st, err
}
