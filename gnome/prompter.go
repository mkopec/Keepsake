// gnome integrates tpm-fido with the GNOME desktop: confirmation dialogs
// through the GNOME Shell system prompter and screen lock detection.
package gnome

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/psanford/tpm-fido/ui"
)

// The system prompter protocol is gcr's internal D-Bus interface
// (gcr/org.gnome.keyring.Prompter.xml), implemented by GNOME Shell, which
// shows the same system-modal dialog as GNOME Keyring's prompts, and by
// gcr-prompter on other desktops. The client exports a callback object,
// asks the prompter to begin prompting, and the prompter calls PromptReady
// on the callback when it can show a prompt and again with the reply.
const (
	prompterBusName    = "org.gnome.keyring.SystemPrompter"
	prompterPath       = "/org/gnome/keyring/Prompter"
	prompterInterface  = "org.gnome.keyring.internal.Prompter"
	callbackInterface  = "org.gnome.keyring.internal.Prompter.Callback"
	callbackPathPrefix = "/org/gnome/keyring/Prompt/tpmfido"
)

// SystemPrompterAvailable reports whether a system prompter currently owns
// its bus name on the session bus.
func SystemPrompterAvailable(conn *dbus.Conn) bool {
	var has bool
	err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, prompterBusName).Store(&has)
	return err == nil && has
}

// Prompter shows confirmation dialogs with the system prompter. It
// implements ui.Confirmer.
type Prompter struct {
	conn *dbus.Conn
	seq  atomic.Uint64
}

func NewPrompter(conn *dbus.Conn) *Prompter {
	return &Prompter{conn: conn}
}

// callback is the exported callback object of one prompt.
type callback struct {
	// owner is the unique bus name of the prompter. Calls from other
	// connections are refused, so other programs can't answer the
	// prompt.
	owner string
	ready chan reply
	done  chan struct{}
	once  sync.Once
}

type reply struct {
	reply    string
	exchange string
}

func (c *callback) PromptReady(sender dbus.Sender, r string, properties map[string]dbus.Variant, exchange string) *dbus.Error {
	if string(sender) != c.owner {
		return dbus.MakeFailedError(errors.New("not the system prompter"))
	}
	select {
	case c.ready <- reply{r, exchange}:
	default:
	}
	return nil
}

func (c *callback) PromptDone(sender dbus.Sender) *dbus.Error {
	if string(sender) != c.owner {
		return dbus.MakeFailedError(errors.New("not the system prompter"))
	}
	c.once.Do(func() { close(c.done) })
	return nil
}

// Confirm shows a confirmation prompt. It implements ui.Confirmer.
func (p *Prompter) Confirm(ctx context.Context, prompt ui.Prompt) (bool, error) {
	ex, err := newSecretExchange()
	if err != nil {
		return false, err
	}
	r, err := p.perform(ctx, "confirm", props(prompt), ex.begin())
	if err != nil {
		return false, err
	}
	return r.reply == "yes", nil
}

// ErrCancelled is returned by Password when the user cancels the prompt.
var ErrCancelled = ui.ErrCancelled

// Password asks for a password. The password travels from the prompter
// encrypted with the gcr secret exchange.
func (p *Prompter) Password(ctx context.Context, prompt ui.PasswordPrompt) (string, error) {
	ex, err := newSecretExchange()
	if err != nil {
		return "", err
	}
	pr := props(prompt.Prompt)
	pr["warning"] = dbus.MakeVariant(prompt.Warning)
	pr["password-new"] = dbus.MakeVariant(false)
	r, err := p.perform(ctx, "password", pr, ex.begin())
	if err != nil {
		return "", err
	}
	if r.reply != "yes" {
		return "", ErrCancelled
	}
	return ex.receive(r.exchange)
}

func props(prompt ui.Prompt) map[string]dbus.Variant {
	return map[string]dbus.Variant{
		"title":          dbus.MakeVariant(prompt.Heading),
		"message":        dbus.MakeVariant(prompt.Heading),
		"description":    dbus.MakeVariant(prompt.Body),
		"warning":        dbus.MakeVariant(""),
		"choice-label":   dbus.MakeVariant(""),
		"continue-label": dbus.MakeVariant(okLabel(prompt)),
		"cancel-label":   dbus.MakeVariant("Cancel"),
	}
}

// perform shows one prompt and returns the prompter's reply.
func (p *Prompter) perform(ctx context.Context, typ string, props map[string]dbus.Variant, exchange string) (reply, error) {
	owner, err := p.owner(ctx)
	if err != nil {
		return reply{}, err
	}

	path := dbus.ObjectPath(fmt.Sprintf("%s/%d", callbackPathPrefix, p.seq.Add(1)))
	cb := &callback{
		owner: owner,
		ready: make(chan reply, 1),
		done:  make(chan struct{}),
	}
	if err := p.conn.Export(cb, path, callbackInterface); err != nil {
		return reply{}, err
	}
	defer p.conn.Export(nil, path, callbackInterface)

	// Calls go to the unique name, so a prompter that restarts in the
	// meantime can't receive them half way through.
	prompter := p.conn.Object(owner, prompterPath)
	if err := prompter.CallWithContext(ctx, prompterInterface+".BeginPrompting", 0, path).Err; err != nil {
		return reply{}, fmt.Errorf("begin prompting err: %w", err)
	}
	defer func() {
		// StopPrompting closes the dialog if it is still shown. Use a
		// fresh context: ctx may be cancelled.
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		prompter.CallWithContext(stopCtx, prompterInterface+".StopPrompting", 0, path)
		select {
		case <-cb.done:
		case <-stopCtx.Done():
		}
	}()

	// wait for the prompter to be ready; other clients' prompts may be
	// shown first
	if _, err := cb.wait(ctx); err != nil {
		return reply{}, err
	}

	err = prompter.CallWithContext(ctx, prompterInterface+".PerformPrompt", 0, path, typ, props, exchange).Err
	if err != nil {
		return reply{}, fmt.Errorf("perform prompt err: %w", err)
	}
	return cb.wait(ctx)
}

// owner returns the unique name of the prompter, starting it if it is
// D-Bus activatable (gcr-prompter) and not running. GNOME Shell's prompter
// always runs.
func (p *Prompter) owner(ctx context.Context) (string, error) {
	var owner string
	bus := p.conn.BusObject()
	if bus.CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, prompterBusName).Store(&owner) == nil {
		return owner, nil
	}
	var started uint32
	if err := bus.CallWithContext(ctx, "org.freedesktop.DBus.StartServiceByName", 0, prompterBusName, uint32(0)).Store(&started); err != nil {
		return "", fmt.Errorf("system prompter not available: %w", err)
	}
	if err := bus.CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, prompterBusName).Store(&owner); err != nil {
		return "", fmt.Errorf("system prompter not available: %w", err)
	}
	return owner, nil
}

// wait returns the next reply from the prompter. A prompter that stops
// prompting without replying counts as a cancelled prompt.
func (c *callback) wait(ctx context.Context) (reply, error) {
	select {
	case r := <-c.ready:
		return r, nil
	case <-c.done:
		return reply{reply: "no"}, nil
	case <-ctx.Done():
		return reply{}, ctx.Err()
	}
}

func okLabel(p ui.Prompt) string {
	if p.OK == "" {
		return "OK"
	}
	return p.OK
}
