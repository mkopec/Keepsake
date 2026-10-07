package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/psanford/tpm-fido/src/ui"
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
//
// The prompt only asks for a PIN for SSH, so the grant only applies to SSH
// requests (relying party IDs starting with "ssh:"): a program can't use
// the prompt to have the user unknowingly confirm a sign in to a website.
const (
	askpassBusName   = "io.github.psanford.TpmFido"
	askpassPath      = "/io/github/psanford/TpmFido"
	askpassInterface = "io.github.psanford.TpmFido.Askpass"

	presenceGrantTTL = 15 * time.Second
	askPINTimeout    = 2 * time.Minute
)

// AskPIN doesn't return the PIN the user typed: any program on the session
// bus can call it, and must not learn the PIN. It returns a random one-time
// token instead, which the SSH agent sends to tpm-fido as if it were the
// PIN. getPinToken recognizes the token's hash and verifies the real PIN,
// which never leaves tpm-fido, against the TPM. The pinToken issued that way
// is only valid for SSH, so a program that calls AskPIN and gets the user to
// type their PIN gains at most one SSH signature.
type presenceGrant struct {
	mu        sync.Mutex
	tokenHash []byte
	pinHash   []byte
	expires   time.Time
}

// set records the PIN the user typed and returns the token for it.
func (g *presenceGrant) set(pin string) string {
	h := sha256.Sum256([]byte(pin))
	// 32 characters: a valid CTAP PIN (4 to 63 bytes)
	token := base64.RawURLEncoding.EncodeToString(mustRand(24))
	th := sha256.Sum256([]byte(token))
	g.mu.Lock()
	defer g.mu.Unlock()
	clear(g.pinHash)
	g.pinHash = h[:16]
	g.tokenHash = th[:16]
	g.expires = time.Now().Add(presenceGrantTTL)
	return token
}

// resolve returns the hash of the real PIN if tokenHash is the hash of an
// unexpired token, and invalidates the token.
func (g *presenceGrant) resolve(tokenHash []byte) []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tokenHash == nil || time.Now().After(g.expires) ||
		subtle.ConstantTimeCompare(g.tokenHash, tokenHash) != 1 {
		return nil
	}
	g.tokenHash = nil
	return append([]byte(nil), g.pinHash...)
}

// consume reports whether there is an unexpired grant for pinHash, and
// removes any grant.
func (g *presenceGrant) consume(pinHash []byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	ok := g.pinHash != nil && pinHash != nil && time.Now().Before(g.expires) &&
		subtle.ConstantTimeCompare(g.pinHash, pinHash) == 1
	clear(g.pinHash)
	g.pinHash = nil
	g.tokenHash = nil
	return ok
}

type askpassService struct {
	s *server
}

// AskPIN asks the user for a security key PIN for message, the prompt of
// the SSH agent, and returns a one-time token to use instead of the PIN.
func (a askpassService) AskPIN(message string) (string, *dbus.Error) {
	ctx, cancel := context.WithTimeout(context.Background(), askPINTimeout)
	defer cancel()

	if a.s.sessionLocked(ctx) {
		return "", dbus.NewError(askpassInterface+".Locked", []interface{}{"session is locked"})
	}

	pin, err := a.s.pe.Password(ctx, sshPINPrompt(message))
	switch {
	case errors.Is(err, ui.ErrCancelled), errors.Is(err, ui.ErrRateLimited):
		return "", dbus.NewError(askpassInterface+".Cancelled", []interface{}{"cancelled"})
	case err != nil:
		return "", dbus.MakeFailedError(err)
	}
	token := a.s.grant.set(pin)
	return token, nil
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
// typing the PIN of this user verified SSH request into tpm-fido's prompt.
func (s *server) usePresenceGrant(uv bool, rpID string) bool {
	if !uv || !strings.HasPrefix(rpID, "ssh:") || !s.grant.consume(s.pin.pinHash) {
		return false
	}
	log.Print("user presence confirmed by the PIN prompt")
	return true
}
