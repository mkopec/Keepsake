// tpm-fido-askpass is an SSH_ASKPASS program that asks with the GNOME
// system prompt, the same dialog as tpm-fido's confirmations and GNOME
// Keyring's prompts.
//
// OpenSSH runs it with the prompt as its only argument and the kind of
// prompt in SSH_ASKPASS_PROMPT:
//
//   - unset: a passphrase or security key PIN, printed on stdout
//   - "confirm": a yes/no question, answered with the exit status
//   - "none": a notification ("Confirm user presence for key ..."), shown
//     until ssh kills the program. tpm-fido shows its own confirmation, so
//     this one shows nothing.
//
// The main use is gcr-ssh-agent, GNOME's SSH agent: it runs an ssh-agent
// that asks for security key PINs through SSH_ASKPASS.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/psanford/tpm-fido/gnome"
	"github.com/psanford/tpm-fido/ui"
)

const timeout = 2 * time.Minute

func main() {
	os.Exit(run())
}

func run() int {
	message := strings.Join(os.Args[1:], " ")
	kind := os.Getenv("SSH_ASKPASS_PROMPT")
	if kind == "none" {
		return 0
	}

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm-fido-askpass: session bus: %s\n", err)
		return 1
	}
	defer conn.Close()
	// D-Bus activates gcr-prompter outside GNOME Shell
	conn.BusObject().Call("org.freedesktop.DBus.StartServiceByName", 0, "org.gnome.keyring.SystemPrompter", uint32(0))
	if !gnome.SystemPrompterAvailable(conn) {
		fmt.Fprintln(os.Stderr, "tpm-fido-askpass: no GNOME system prompter (GNOME Shell or gcr) available")
		return 1
	}
	p := gnome.NewPrompter(conn)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if kind == "confirm" {
		ok, err := p.Confirm(ctx, confirmPrompt(message))
		if err != nil {
			fmt.Fprintf(os.Stderr, "tpm-fido-askpass: %s\n", err)
			return 1
		}
		if !ok {
			return 1
		}
		return 0
	}

	secret, err := p.Password(ctx, passwordPrompt(message))
	if errors.Is(err, gnome.ErrCancelled) {
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm-fido-askpass: %s\n", err)
		return 1
	}
	fmt.Println(secret)
	return 0
}

// ssh's prompts are full sentences ending in ": " or "? ". They become the
// body; the heading names the action, as GNOME's HIG asks.
func body(message string) string {
	return strings.TrimRight(strings.TrimSpace(message), ":")
}

func passwordPrompt(message string) gnome.PasswordPrompt {
	p := gnome.PasswordPrompt{Prompt: ui.Prompt{
		Heading: "Enter SSH Key Passphrase",
		Body:    body(message),
		OK:      "Unlock",
	}}
	if strings.Contains(message, "PIN") {
		p.Heading = "Enter Security Key PIN"
		p.OK = "Continue"
	}
	return p
}

func confirmPrompt(message string) ui.Prompt {
	return ui.Prompt{
		Heading: "Allow Use of SSH Key?",
		Body:    body(message),
		OK:      "Allow",
	}
}
