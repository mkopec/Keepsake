package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/psanford/tpm-fido/gnome"
	"github.com/psanford/tpm-fido/pinentry"
	"github.com/psanford/tpm-fido/ui"
)

var promptBackend = flag.String("prompt", "auto", "confirmation dialogs: auto (GNOME system prompt if available, else pinentry), gnome or pinentry")
var lockCheck = flag.Bool("lock-check", true, "refuse requests while the session is locked or inactive")
var askpassServiceFlag = flag.Bool("askpass-service", true, "let tpm-fido-askpass ask for SSH security key PINs through tpm-fido (one prompt instead of two)")

// Locker reports whether the user's session is locked.
type Locker interface {
	Locked(ctx context.Context) (bool, error)
}

// setupDesktop picks the confirmation dialog backend and the screen lock
// check.
func (s *server) setupDesktop() error {
	conn, connErr := dbus.ConnectSessionBus()

	var confirmer ui.Confirmer
	switch *promptBackend {
	case "auto":
		if connErr == nil && gnome.SystemPrompterAvailable(conn) {
			log.Print("showing dialogs with the GNOME system prompter")
			confirmer = gnome.NewPrompter(conn)
		}
	case "gnome":
		if connErr != nil {
			return fmt.Errorf("connect to session bus: %w", connErr)
		}
		// the prompter is D-Bus activatable, e.g. gcr-prompter
		log.Print("showing dialogs with the GNOME system prompter")
		confirmer = gnome.NewPrompter(conn)
	case "pinentry":
	default:
		return fmt.Errorf("unknown -prompt %q", *promptBackend)
	}
	if confirmer == nil {
		if pinentry.FindPinentryGUIPath() == "" {
			log.Printf("warning: no gui pinentry binary detected in PATH. tpm-fido may not work correctly without a gui based pinentry")
		}
		log.Print("showing dialogs with pinentry")
		confirmer = pinentry.New()
	}
	s.pe = ui.New(confirmer)
	s.pe.Allow = s.dialogs.allow

	if *askpassServiceFlag && connErr == nil {
		if err := s.exportAskpassService(conn); err != nil {
			log.Printf("askpass service not available: %s", err)
		}
	}

	if *lockCheck {
		if connErr != nil {
			log.Printf("session bus unavailable (%s), only asking logind about the screen lock", connErr)
			conn = nil
		}
		s.locker = gnome.NewSession(conn)
	}
	return nil
}

var lockErrOnce sync.Once

// logName returns a relying party ID or user name for the log: they are
// only logged with -verbose, since the journal is kept for a long time.
func logName(name string) string {
	if *verbose {
		return name
	}
	return "(hidden)"
}

// sessionLocked reports whether requests must be refused because the
// session is locked. If the lock state is unknown, requests are allowed:
// the check only avoids prompts nobody can answer and requests while the
// user is away.
func (s *server) sessionLocked(ctx context.Context) bool {
	if s.locker == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	locked, err := s.locker.Locked(ctx)
	if err != nil {
		// Fail closed once the lock state could be read: an error then
		// may mean something interferes with the check. If it never
		// could (no logind, no GNOME), allow requests.
		if s.lockKnown.Load() {
			log.Printf("can't tell whether the session is locked, refusing request: %s", err)
			return true
		}
		lockErrOnce.Do(func() {
			log.Printf("can't tell whether the session is locked, allowing requests: %s", err)
		})
		return false
	}
	s.lockKnown.Store(true)
	if locked {
		log.Print("session is locked or inactive, refusing request")
	}
	return locked
}
