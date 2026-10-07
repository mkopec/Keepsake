package main

import (
	"fmt"
	"log"

	"github.com/mkopec/keepsake/src/fidohid"
)

// reset handles authenticatorReset: it irrecoverably invalidates every
// credential, deletes the passkeys and removes the PIN.
//
// Hardware authenticators only accept a reset shortly after being plugged
// in. Keepsake has no equivalent of plugging in, so it relies on the user
// confirming the reset instead.
func (s *server) reset(evt fidohid.AuthEvent, ka *keepalive) (interface{}, error) {
	log.Print("got ctap2 Reset")

	if err := s.confirmPresence(evt, ka, resetPrompt()); err != nil {
		return nil, err
	}

	if err := s.signer.Reset(); err != nil {
		return nil, fmt.Errorf("reset err: %w", err)
	}
	s.storeKey = nil
	s.pin = newPINState()
	s.nextAssertion = nil
	s.credMgmt = nil

	// The store can't be decrypted anymore; a failure here only leaves an
	// unreadable file behind.
	if err := s.passkeys.Remove(); err != nil {
		log.Printf("remove passkey store err: %s", err)
	}

	log.Print("authenticator reset")
	return nil, nil
}
