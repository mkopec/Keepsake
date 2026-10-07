package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"

	"github.com/psanford/tpm-fido/ctap2"
	"github.com/psanford/tpm-fido/tpm"
)

// hmacSecretCreate reports whether a MakeCredential request asks for the
// hmac-secret extension.
func hmacSecretCreate(extensions ctap2.Extensions) (bool, error) {
	raw, ok := extensions[ctap2.ExtHMACSecret]
	if !ok {
		return false, nil
	}
	var enabled bool
	if err := ctap2.Unmarshal(raw, &enabled); err != nil {
		return false, err
	}
	return enabled, nil
}

// hmacSecretRequest is a validated hmac-secret GetAssertion input.
type hmacSecretRequest struct {
	proto  ctap2.PINProtocol
	shared []byte
	salts  [][]byte
}

// parseHMACSecretGet validates the hmac-secret input of a GetAssertion
// request. It returns nil if the extension wasn't requested.
func (s *server) parseHMACSecretGet(extensions ctap2.Extensions) (*hmacSecretRequest, error) {
	raw, ok := extensions[ctap2.ExtHMACSecret]
	if !ok {
		return nil, nil
	}
	var in ctap2.HMACSecretInput
	if err := ctap2.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	if in.KeyAgreement == nil || in.SaltEnc == nil || in.SaltAuth == nil {
		return nil, ctap2.ErrMissingParameter
	}

	version := in.PinUvAuthProtocol
	if version == 0 {
		version = 1
	}
	proto := ctap2.LookupPINProtocol(version)
	if proto == nil {
		return nil, ctap2.ErrInvalidParameter
	}

	shared, err := s.sharedSecret(proto, in.KeyAgreement)
	if err != nil {
		return nil, err
	}
	if !ctap2.VerifyPINAuth(proto, shared, in.SaltEnc, in.SaltAuth) {
		return nil, ctap2.ErrPinAuthInvalid
	}
	salts, err := proto.Decrypt(shared, in.SaltEnc)
	if err != nil {
		return nil, err
	}
	if len(salts) != 32 && len(salts) != 64 {
		return nil, ctap2.ErrInvalidLength
	}

	req := &hmacSecretRequest{proto: proto, shared: shared}
	for len(salts) > 0 {
		req.salts = append(req.salts, salts[:32])
		salts = salts[32:]
	}
	return req, nil
}

// hmacSecretOutput computes the encoded extension output for credID. It
// returns nil if the credential doesn't have hmac-secret enabled.
func (s *server) hmacSecretOutput(req *hmacSecretRequest, credID, rpIDHash []byte, uv bool) ([]byte, error) {
	var uvPinHash []byte
	if uv {
		if s.pin.pinHash == nil {
			return nil, errors.New("user verified without a PIN hash")
		}
		uvPinHash = s.pin.pinHash
	}

	credRandom, err := s.signer.HMACSecret(credID, rpIDHash, uvPinHash)
	if errors.Is(err, tpm.ErrHMACSecretNotEnabled) {
		log.Print("hmac-secret requested for a credential created without it")
		return nil, nil
	}
	if errors.Is(err, tpm.ErrLockout) {
		return nil, ctap2.ErrPinAuthBlocked
	}
	if err != nil {
		return nil, fmt.Errorf("hmac-secret err: %w", err)
	}

	var outputs []byte
	for _, salt := range req.salts {
		mac := hmac.New(sha256.New, credRandom)
		mac.Write(salt)
		outputs = mac.Sum(outputs)
	}

	return ctap2.Marshal(map[string][]byte{
		ctap2.ExtHMACSecret: req.proto.Encrypt(req.shared, outputs),
	})
}
