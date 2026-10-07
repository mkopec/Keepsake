package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/psanford/tpm-fido/ctap2"
	"github.com/psanford/tpm-fido/fidohid"
	"github.com/psanford/tpm-fido/tpm"
)

const (
	maxPINRetries = 8
	// consecutive wrong PINs after which the PIN is blocked until restart
	maxConsecutivePINFailures = 3
	minPINLength              = 4
	paddedPINLength           = 64

	// pinTokenLifetime is how long a pinToken (and the PIN hash it was
	// issued for, which the TPM needs for PIN-bound credentials) stays
	// valid. Platforms use the token right after getting it.
	pinTokenLifetime = time.Minute
)

// PINStore persists the clientPIN state. pinHash is LEFT(SHA-256(PIN), 16).
type PINStore interface {
	PINSet() (bool, error)
	// SetPIN stores a new PIN. oldPinHash is the current PIN hash when
	// changing the PIN and nil otherwise.
	SetPIN(pinHash, oldPinHash []byte, retries int) error
	PINRetries() (int, error)
	SetPINRetries(retries int) error
	// VerifyPIN returns tpm.ErrLockout if the PIN can't be checked right now.
	VerifyPIN(pinHash []byte) (bool, error)
}

// pinState is the volatile clientPIN state, reset when tpm-fido restarts
// (the equivalent of an authenticator power cycle).
type pinState struct {
	keyAgreement *ecdh.PrivateKey
	pinToken     []byte
	// pinHash is the hash of the PIN that pinToken was issued for. It is
	// needed to use the TPM's UV key for hmac-secret.
	pinHash      []byte
	tokenExpires time.Time
	// sshOnly is set if the pinToken was issued for an askpass token:
	// it is only valid for SSH relying parties
	sshOnly             bool
	consecutiveFailures int
}

// expire invalidates the pinToken and wipes the PIN hash once they expired.
// It must run on the request goroutine.
func (ps *pinState) expire() {
	if ps.pinHash != nil && time.Now().After(ps.tokenExpires) {
		ps.regeneratePINToken()
	}
}

func newPINState() *pinState {
	var ps pinState
	ps.regenerateKeyAgreement()
	ps.regeneratePINToken()
	return &ps
}

func (ps *pinState) regenerateKeyAgreement() {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ps.keyAgreement = k
}

func (ps *pinState) regeneratePINToken() {
	clear(ps.pinToken)
	clear(ps.pinHash)
	ps.pinToken = mustRand(32)
	ps.pinHash = nil
	ps.sshOnly = false
}

func (s *server) clientPIN(evt fidohid.AuthEvent, ka *keepalive, req *ctap2.ClientPINReq) (interface{}, error) {
	if req.SubCommand == 0 {
		return nil, ctap2.ErrMissingParameter
	}
	proto := ctap2.LookupPINProtocol(req.PinProtocol)
	if proto == nil {
		if req.PinProtocol == 0 {
			return nil, ctap2.ErrMissingParameter
		}
		return nil, ctap2.ErrInvalidParameter
	}

	log.Printf("got ctap2 ClientPIN subcommand=0x%02x protocol=%d", req.SubCommand, req.PinProtocol)

	switch req.SubCommand {
	case ctap2.PINGetRetries:
		set, err := s.pins.PINSet()
		if err != nil {
			return nil, err
		}
		retries := maxPINRetries
		if set {
			if retries, err = s.pins.PINRetries(); err != nil {
				return nil, err
			}
		}
		return ctap2.ClientPINResp{Retries: &retries}, nil
	case ctap2.PINGetKeyAgreement:
		return ctap2.ClientPINResp{
			KeyAgreement: ctap2.KeyAgreementCOSEKey(s.pin.keyAgreement.PublicKey()),
		}, nil
	case ctap2.PINSetPIN:
		return nil, s.setPIN(evt, ka, proto, req)
	case ctap2.PINChangePIN:
		return nil, s.changePIN(proto, req)
	case ctap2.PINGetPINToken:
		return s.getPINToken(proto, req)
	default:
		return nil, ctap2.ErrInvalidParameter
	}
}

func (s *server) sharedSecret(proto ctap2.PINProtocol, platformKey *ctap2.COSEKey) ([]byte, error) {
	pub, err := platformKey.ECDHPublicKey()
	if err != nil {
		return nil, err
	}
	z, err := s.pin.keyAgreement.ECDH(pub)
	if err != nil {
		return nil, ctap2.ErrInvalidParameter
	}
	return proto.SharedSecret(z), nil
}

func (s *server) setPIN(evt fidohid.AuthEvent, ka *keepalive, proto ctap2.PINProtocol, req *ctap2.ClientPINReq) error {
	if req.KeyAgreement == nil || req.PinAuth == nil || req.NewPinEnc == nil {
		return ctap2.ErrMissingParameter
	}
	set, err := s.pins.PINSet()
	if err != nil {
		return err
	}
	if set {
		return ctap2.ErrPinAuthInvalid
	}

	shared, err := s.sharedSecret(proto, req.KeyAgreement)
	if err != nil {
		return err
	}
	if !ctap2.VerifyPINAuth(proto, shared, req.NewPinEnc, req.PinAuth) {
		return ctap2.ErrPinAuthInvalid
	}
	pinHash, err := decryptNewPIN(proto, shared, req.NewPinEnc)
	if err != nil {
		return err
	}

	// CTAP doesn't need user presence to set the first PIN, but tpm-fido
	// is never unplugged: without it, any program that can open the
	// device could set a PIN the user doesn't know.
	if err := s.confirmPresence(evt, ka, setPINPrompt()); err != nil {
		return err
	}

	if err := s.pins.SetPIN(pinHash, nil, maxPINRetries); err != nil {
		return err
	}
	s.pin.regeneratePINToken()
	log.Print("PIN set")
	return nil
}

func (s *server) changePIN(proto ctap2.PINProtocol, req *ctap2.ClientPINReq) error {
	if req.KeyAgreement == nil || req.PinAuth == nil || req.NewPinEnc == nil || req.PinHashEnc == nil {
		return ctap2.ErrMissingParameter
	}
	set, err := s.pins.PINSet()
	if err != nil {
		return err
	}
	if !set {
		return ctap2.ErrPinNotSet
	}

	shared, err := s.sharedSecret(proto, req.KeyAgreement)
	if err != nil {
		return err
	}
	msg := append(append([]byte(nil), req.NewPinEnc...), req.PinHashEnc...)
	if !ctap2.VerifyPINAuth(proto, shared, msg, req.PinAuth) {
		return ctap2.ErrPinAuthInvalid
	}
	oldPinHash, _, err := s.verifyPINHash(proto, shared, req.PinHashEnc, false)
	if err != nil {
		return err
	}
	pinHash, err := decryptNewPIN(proto, shared, req.NewPinEnc)
	if err != nil {
		return err
	}

	if err := s.pins.SetPIN(pinHash, oldPinHash, maxPINRetries); err != nil {
		return err
	}
	s.pin.regeneratePINToken()
	log.Print("PIN changed")
	return nil
}

func (s *server) getPINToken(proto ctap2.PINProtocol, req *ctap2.ClientPINReq) (interface{}, error) {
	if req.KeyAgreement == nil || req.PinHashEnc == nil {
		return nil, ctap2.ErrMissingParameter
	}
	set, err := s.pins.PINSet()
	if err != nil {
		return nil, err
	}
	if !set {
		return nil, ctap2.ErrPinNotSet
	}

	shared, err := s.sharedSecret(proto, req.KeyAgreement)
	if err != nil {
		return nil, err
	}
	pinHash, sshOnly, err := s.verifyPINHash(proto, shared, req.PinHashEnc, true)
	if err != nil {
		return nil, err
	}

	s.pin.regeneratePINToken()
	s.pin.pinHash = pinHash
	s.pin.sshOnly = sshOnly
	s.pin.tokenExpires = time.Now().Add(pinTokenLifetime)
	return ctap2.ClientPINResp{PinToken: proto.Encrypt(shared, s.pin.pinToken)}, nil
}

// verifyPINHash checks the encrypted PIN hash sent by the platform against
// the stored PIN, maintaining the retry counters. It returns the PIN hash.
// With allowAskpassToken, the hash of an askpass token (see
// askpassservice.go) stands for the PIN the user typed, and sshOnly is
// returned true.
func (s *server) verifyPINHash(proto ctap2.PINProtocol, shared, pinHashEnc []byte, allowAskpassToken bool) (pinHash []byte, sshOnly bool, err error) {
	retries, err := s.pins.PINRetries()
	if err != nil {
		return nil, false, err
	}
	if retries <= 0 {
		return nil, false, ctap2.ErrPinBlocked
	}
	if s.pin.consecutiveFailures >= maxConsecutivePINFailures {
		return nil, false, ctap2.ErrPinAuthBlocked
	}

	pinHash, err = proto.Decrypt(shared, pinHashEnc)
	if err != nil {
		return nil, false, err
	}
	if len(pinHash) != 16 {
		return nil, false, ctap2.ErrInvalidParameter
	}
	if allowAskpassToken {
		if real := s.grant.resolve(pinHash); real != nil {
			pinHash, sshOnly = real, true
		}
	}

	// Count the attempt before checking it, so that cutting power (killing
	// tpm-fido) after a wrong guess doesn't save a retry.
	if err := s.pins.SetPINRetries(retries - 1); err != nil {
		return nil, false, err
	}

	ok, err := s.pins.VerifyPIN(pinHash)
	if errors.Is(err, tpm.ErrLockout) {
		// The TPM didn't check the PIN, so don't count the attempt.
		log.Printf("PIN check refused: %s", err)
		if err := s.pins.SetPINRetries(retries); err != nil {
			return nil, false, err
		}
		return nil, false, ctap2.ErrPinAuthBlocked
	}
	if err != nil {
		return nil, false, err
	}

	if !ok {
		s.pin.regenerateKeyAgreement()
		s.pin.consecutiveFailures++
		log.Printf("wrong PIN, %d retries left", retries-1)
		switch {
		case retries-1 <= 0:
			return nil, false, ctap2.ErrPinBlocked
		case s.pin.consecutiveFailures >= maxConsecutivePINFailures:
			return nil, false, ctap2.ErrPinAuthBlocked
		}
		return nil, false, ctap2.ErrPinInvalid
	}

	s.pin.consecutiveFailures = 0
	if err := s.pins.SetPINRetries(maxPINRetries); err != nil {
		return nil, false, err
	}
	return pinHash, sshOnly, nil
}

// decryptNewPIN decrypts and validates a padded new PIN and returns its
// hash.
func decryptNewPIN(proto ctap2.PINProtocol, shared, newPinEnc []byte) ([]byte, error) {
	padded, err := proto.Decrypt(shared, newPinEnc)
	if err != nil {
		return nil, err
	}
	if len(padded) != paddedPINLength {
		return nil, ctap2.ErrInvalidParameter
	}

	pin := bytes.TrimRight(padded, "\x00")
	if len(pin) == paddedPINLength {
		// the padding must include at least one zero byte
		return nil, ctap2.ErrPinPolicyViolation
	}
	if !utf8.Valid(pin) || utf8.RuneCount(pin) < minPINLength {
		return nil, ctap2.ErrPinPolicyViolation
	}

	h := sha256.Sum256(pin)
	return h[:16], nil
}

// checkPINUVAuth handles the pinUvAuthParam of MakeCredential and
// GetAssertion. It returns true if the request was authorized with a valid
// pinToken (user verified).
func (s *server) checkPINUVAuth(param *[]byte, protocol uint, clientDataHash []byte, pinRequired bool, rpID string) (bool, error) {
	set, err := s.pins.PINSet()
	if err != nil {
		return false, err
	}

	if param == nil {
		if pinRequired && set {
			return false, ctap2.ErrPinRequired
		}
		return false, nil
	}

	proto := ctap2.LookupPINProtocol(protocol)
	if proto == nil {
		if protocol == 0 {
			return false, ctap2.ErrMissingParameter
		}
		return false, ctap2.ErrInvalidParameter
	}
	if !set {
		return false, ctap2.ErrPinNotSet
	}
	if !ctap2.VerifyPINAuth(proto, s.pin.pinToken, clientDataHash, *param) {
		return false, ctap2.ErrPinAuthInvalid
	}
	if s.pin.sshOnly && !strings.HasPrefix(rpID, "ssh:") {
		log.Print("pinToken issued for an askpass token used for a non-SSH relying party, refused")
		return false, ctap2.ErrPinAuthInvalid
	}
	return true, nil
}
