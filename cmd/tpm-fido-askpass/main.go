// tpm-fido-askpass is an SSH_ASKPASS program for GNOME. OpenSSH runs it
// with the prompt as its only argument and the kind of prompt in
// SSH_ASKPASS_PROMPT:
//
//   - unset: a passphrase or security key PIN, printed on stdout. If
//     tpm-fido runs, it asks for security key PINs itself: one prompt both
//     takes the PIN and confirms the signature, instead of a PIN prompt
//     followed by tpm-fido's confirmation. Otherwise, and for passphrases,
//     it asks with the GNOME system prompt.
//   - "confirm": a yes/no question, answered with the exit status.
//   - "none": a notification ("Confirm user presence for key ..."), shown
//     until ssh kills the program. It is shown as a desktop notification,
//     unless tpm-fido is handling the request and shows its own dialog.
//
// Without a GNOME system prompter it runs the system's default askpass
// program ($TPMFIDO_ASKPASS_FALLBACK, or OpenSSH's ssh-askpass).
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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/psanford/tpm-fido/gnome"
	"github.com/psanford/tpm-fido/ui"
)

const (
	timeout = 2 * time.Minute

	tpmFidoBusName   = "io.github.psanford.TpmFido"
	tpmFidoPath      = "/io/github/psanford/TpmFido"
	tpmFidoInterface = "io.github.psanford.TpmFido.Askpass"

	// how long to wait for the security key request after a "touch"
	// notification starts, to tell whether tpm-fido handles it
	tpmFidoWait = time.Second
)

var fallbackAskpass = []string{
	"/usr/lib/ssh/ssh-askpass",
	"/usr/libexec/openssh/ssh-askpass",
	"/usr/lib/openssh/ssh-askpass",
	"/usr/bin/ssh-askpass",
}

func main() {
	os.Exit(run())
}

func run() int {
	start := time.Now()
	message := strings.Join(os.Args[1:], " ")
	kind := os.Getenv("SSH_ASKPASS_PROMPT")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return fallback("session bus: " + err.Error())
	}
	defer conn.Close()

	if kind == "none" {
		return notify(ctx, conn, message, start)
	}

	if kind == "" && strings.Contains(message, "PIN") && hasOwner(conn, tpmFidoBusName) {
		pin, err := askTpmFido(ctx, conn, message)
		var derr dbus.Error
		switch {
		case err == nil:
			fmt.Println(pin)
			return 0
		case errors.As(err, &derr) && (derr.Name == tpmFidoInterface+".Cancelled" || derr.Name == tpmFidoInterface+".Locked"):
			return 1
		case ctx.Err() != nil:
			return 1
		}
		// e.g. tpm-fido is busy with another dialog
		fmt.Fprintf(os.Stderr, "tpm-fido-askpass: tpm-fido: %s\n", err)
	}

	// D-Bus activates gcr-prompter outside GNOME Shell
	conn.BusObject().Call("org.freedesktop.DBus.StartServiceByName", 0, "org.gnome.keyring.SystemPrompter", uint32(0))
	if !gnome.SystemPrompterAvailable(conn) {
		return fallback("no GNOME system prompter (GNOME Shell or gcr)")
	}
	p := gnome.NewPrompter(conn)

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
	if errors.Is(err, ui.ErrCancelled) {
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tpm-fido-askpass: %s\n", err)
		return 1
	}
	fmt.Println(secret)
	return 0
}

func hasOwner(conn *dbus.Conn, name string) bool {
	var has bool
	err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, name).Store(&has)
	return err == nil && has
}

func askTpmFido(ctx context.Context, conn *dbus.Conn, message string) (string, error) {
	var pin string
	err := conn.Object(tpmFidoBusName, tpmFidoPath).
		CallWithContext(ctx, tpmFidoInterface+".AskPIN", 0, message).Store(&pin)
	return pin, err
}

// tpmFidoHandles reports whether tpm-fido received a security key request
// since start, waiting up to tpmFidoWait for one.
func tpmFidoHandles(ctx context.Context, conn *dbus.Conn, start time.Time) bool {
	if !hasOwner(conn, tpmFidoBusName) {
		return false
	}
	obj := conn.Object(tpmFidoBusName, tpmFidoPath)
	deadline := time.Now().Add(tpmFidoWait)
	for {
		var age uint64
		if err := obj.CallWithContext(ctx, tpmFidoInterface+".LastRequestAge", 0).Store(&age); err != nil {
			return false
		}
		// the agent starts the notification just before the request
		if age <= uint64(time.Since(start).Milliseconds())+500 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// notify shows the "touch your security key" notification until ssh kills
// the program, unless tpm-fido shows its own dialog.
func notify(ctx context.Context, conn *dbus.Conn, message string, start time.Time) int {
	if tpmFidoHandles(ctx, conn, start) {
		<-ctx.Done()
		return 0
	}
	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	var id uint32
	err := obj.CallWithContext(ctx, "org.freedesktop.Notifications.Notify", 0,
		"SSH", uint32(0), "auth-smartcard-symbolic", "Touch Your Security Key", notificationBody(message),
		[]string{}, map[string]dbus.Variant{
			"transient": dbus.MakeVariant(true),
			"urgency":   dbus.MakeVariant(byte(2)),
		}, int32(0)).Store(&id)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "tpm-fido-askpass: notification: %s\n", err)
		}
		<-ctx.Done()
		return 0
	}
	<-ctx.Done()
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	obj.CallWithContext(closeCtx, "org.freedesktop.Notifications.CloseNotification", 0, id)
	return 0
}

// fallback runs another askpass program. It doesn't return if one is
// found.
func fallback(reason string) int {
	self, _ := os.Executable()
	candidates := fallbackAskpass
	if f := os.Getenv("TPMFIDO_ASKPASS_FALLBACK"); f != "" {
		candidates = []string{f}
	}
	for _, c := range candidates {
		if r, err := filepath.EvalSymlinks(c); err != nil || r == self {
			continue
		}
		if err := syscall.Exec(c, append([]string{c}, os.Args[1:]...), os.Environ()); err == nil {
			return 0
		}
	}
	fmt.Fprintf(os.Stderr, "tpm-fido-askpass: %s, and no other askpass program found\n", reason)
	return 1
}

// ssh's prompts are full sentences ending in ": " or "? ". They become the
// body; the heading names the action, as GNOME's HIG asks.
func body(message string) string {
	return strings.TrimRight(strings.TrimSpace(message), ":")
}

func notificationBody(message string) string {
	return strings.Replace(body(message), "Confirm user presence for", "Confirm the use of", 1)
}

func passwordPrompt(message string) ui.PasswordPrompt {
	p := ui.PasswordPrompt{Prompt: ui.Prompt{
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
