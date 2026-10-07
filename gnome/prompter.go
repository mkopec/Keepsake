// gnome integrates tpm-fido with the GNOME desktop: confirmation dialogs
// through the GNOME Shell system prompter and screen lock detection.
package gnome

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
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
	ready chan string
	done  chan struct{}
	once  sync.Once
}

func (c *callback) PromptReady(sender dbus.Sender, reply string, properties map[string]dbus.Variant, exchange string) *dbus.Error {
	if string(sender) != c.owner {
		return dbus.MakeFailedError(errors.New("not the system prompter"))
	}
	select {
	case c.ready <- reply:
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

func (p *Prompter) Confirm(ctx context.Context, prompt ui.Prompt) (bool, error) {
	var owner string
	err := p.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, prompterBusName).Store(&owner)
	if err != nil {
		return false, fmt.Errorf("system prompter not available: %w", err)
	}

	path := dbus.ObjectPath(fmt.Sprintf("%s/%d", callbackPathPrefix, p.seq.Add(1)))
	cb := &callback{
		owner: owner,
		ready: make(chan string, 1),
		done:  make(chan struct{}),
	}
	if err := p.conn.Export(cb, path, callbackInterface); err != nil {
		return false, err
	}
	defer p.conn.Export(nil, path, callbackInterface)

	// Calls go to the unique name, so a prompter that restarts in the
	// meantime can't receive them half way through.
	prompter := p.conn.Object(owner, prompterPath)
	if err := prompter.CallWithContext(ctx, prompterInterface+".BeginPrompting", 0, path).Err; err != nil {
		return false, fmt.Errorf("begin prompting err: %w", err)
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
		return false, err
	}

	exchange, err := beginSecretExchange()
	if err != nil {
		return false, err
	}
	props := map[string]dbus.Variant{
		"title":          dbus.MakeVariant(prompt.Heading),
		"message":        dbus.MakeVariant(prompt.Heading),
		"description":    dbus.MakeVariant(prompt.Body),
		"warning":        dbus.MakeVariant(""),
		"choice-label":   dbus.MakeVariant(""),
		"continue-label": dbus.MakeVariant(okLabel(prompt)),
		"cancel-label":   dbus.MakeVariant("Cancel"),
	}
	err = prompter.CallWithContext(ctx, prompterInterface+".PerformPrompt", 0, path, "confirm", props, exchange).Err
	if err != nil {
		return false, fmt.Errorf("perform prompt err: %w", err)
	}

	reply, err := cb.wait(ctx)
	if err != nil {
		return false, err
	}
	return reply == "yes", nil
}

// wait returns the next reply from the prompter. A prompter that stops
// prompting without replying counts as a cancelled prompt.
func (c *callback) wait(ctx context.Context) (string, error) {
	select {
	case reply := <-c.ready:
		return reply, nil
	case <-c.done:
		return "no", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func okLabel(p ui.Prompt) string {
	if p.OK == "" {
		return "OK"
	}
	return p.OK
}

// The prompter refuses a prompt without a valid gcr secret exchange
// ("sx-aes-1"), even a confirmation that doesn't transfer a secret. The
// exchange begins with a Diffie-Hellman public key in the 1536 bit MODP
// group (RFC 3526 group 5). No secret is ever sent, so the private key is
// thrown away.
var (
	modp1536, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
	modpGenerator = big.NewInt(2)
)

func beginSecretExchange() (string, error) {
	priv, err := rand.Int(rand.Reader, new(big.Int).Sub(modp1536, big.NewInt(2)))
	if err != nil {
		return "", err
	}
	priv.Add(priv, big.NewInt(1))
	pub := new(big.Int).Exp(modpGenerator, priv, modp1536)
	return "[sx-aes-1]\npublic=" + base64.StdEncoding.EncodeToString(pub.Bytes()) + "\n", nil
}
