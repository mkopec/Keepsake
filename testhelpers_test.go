package main

import "github.com/psanford/tpm-fido/ctap2"

// alwaysPIN is a PINStore with a PIN set.
type alwaysPIN struct{}

func (alwaysPIN) PINSet() (bool, error)           { return true, nil }
func (alwaysPIN) SetPIN(_, _ []byte, _ int) error { return nil }
func (alwaysPIN) PINRetries() (int, error)        { return 8, nil }
func (alwaysPIN) SetPINRetries(int) error         { return nil }
func (alwaysPIN) VerifyPIN([]byte) (bool, error)  { return true, nil }

func ctap2PINAuth(token, msg []byte) []byte {
	return ctap2.LookupPINProtocol(2).Authenticate(token, msg)
}
