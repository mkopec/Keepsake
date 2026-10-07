package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/psanford/tpm-fido/ui"
)

// SSH agents ask for the PIN of verify-required security keys with
// SSH_ASKPASS, and tpm-fido then asks the user to confirm the signature:
// two dialogs. tpm-fido-askpass instead asks tpm-fido for the PIN over
// D-Bus, and tpm-fido shows a single prompt. Typing the PIN into a prompt
// tpm-fido showed proves that the user is present, so tpm-fido grants
// presence once: the next GetAssertion whose verified PIN is the one typed,
// within presenceGrantTTL, doesn't show the confirmation dialog.
//
// Any program on the session bus can ask tpm-fido to show the prompt, but
// it can't answer it for the user. It could ask for the PIN this way and
// receive it, but it could equally show its own (or the system prompter's)
// PIN prompt. A program that already knows the PIN and races the user's
// request uses up the grant, and the user's request shows the usual dialog.
const (
	askpassBusName   = "io.github.psanford.TpmFido"
	askpassPath      = "/io/github/psanford/TpmFido"
	askpassInterface = "io.github.psanford.TpmFido.Askpass"

	presenceGrantTTL = 15 * time.Second
	askPINTimeout    = 2 * time.Minute
)

type presenceGrant struct {
	mu      sync.Mutex
	pinHash []byte
	expires time.Time
}

func (g *presenceGrant) set(pin string) {
	h := sha256.Sum256([]byte(pin))
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pinHash = h[:16]
	g.expires = time.Now().Add(presenceGrantTTL)
}

// consume reports whether there is an unexpired grant for pinHash, and
// removes any grant.
func (g *presenceGrant) consume(pinHash []byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	ok := g.pinHash != nil && pinHash != nil && time.Now().Before(g.expires) &&
		subtle.ConstantTimeCompare(g.pinHash, pinHash) == 1
	g.pinHash = nil
	return ok
}

type askpassService struct {
	s *server
}

// AskPIN asks the user for a security key PIN for message, the prompt of
// the SSH agent.
func (a askpassService) AskPIN(message string) (string, *dbus.Error) {
	ctx, cancel := context.WithTimeout(context.Background(), askPINTimeout)
	defer cancel()

	if a.s.sessionLocked(ctx) {
		return "", dbus.NewError(askpassInterface+".Locked", []interface{}{"session is locked"})
	}
	pin, err := a.s.pe.Password(ctx, sshPINPrompt(message))
	switch {
	case errors.Is(err, ui.ErrCancelled):
		return "", dbus.NewError(askpassInterface+".Cancelled", []interface{}{"cancelled"})
	case err != nil:
		return "", dbus.MakeFailedError(err)
	}
	a.s.grant.set(pin)
	return pin, nil
}

// LastRequestAge returns the milliseconds since tpm-fido last received a
// request that may need confirmation, or the maximum value if it never did.
func (a askpassService) LastRequestAge() (uint64, *dbus.Error) {
	last := a.s.lastRequest.Load()
	if last == 0 {
		return ^uint64(0), nil
	}
	return uint64(time.Since(time.Unix(0, last)).Milliseconds()), nil
}

// exportAskpassService offers the askpass service on the session bus.
func (s *server) exportAskpassService(conn *dbus.Conn) error {
	if err := conn.Export(askpassService{s}, askpassPath, askpassInterface); err != nil {
		return err
	}
	reply, err := conn.RequestName(askpassBusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("%s is already owned, another tpm-fido is running", askpassBusName)
	}
	return nil
}

func (s *server) noteRequest() {
	s.lastRequest.Store(time.Now().UnixNano())
}

// usePresenceGrant reports whether the presence of the user was proven by
// typing the PIN of this user verified request into tpm-fido's prompt.
func (s *server) usePresenceGrant(uv bool) bool {
	if !uv || !s.grant.consume(s.pin.pinHash) {
		return false
	}
	log.Print("user presence confirmed by the PIN prompt")
	return true
}
