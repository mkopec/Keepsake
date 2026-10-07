package gnome

import (
	"context"
	"encoding/base64"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/psanford/tpm-fido/ui"
)

func TestSecretExchangeFormat(t *testing.T) {
	ex, err := beginSecretExchange()
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "[sx-aes-1]\npublic="
	if !strings.HasPrefix(ex, prefix) || !strings.HasSuffix(ex, "\n") {
		t.Fatalf("unexpected exchange %q", ex)
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(ex[len(prefix):], "\n"))
	if err != nil {
		t.Fatal(err)
	}
	y := new(big.Int).SetBytes(pub)
	if len(pub) > 192 || y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(modp1536) >= 0 {
		t.Fatalf("public value out of range (%d bytes)", len(pub))
	}
}

// TestSystemPrompter needs a system prompter on the session bus and an X
// display with xdotool, e.g. scripts/test-gnome-prompter.sh. It drives the
// dialog with key presses.
func TestSystemPrompter(t *testing.T) {
	if os.Getenv("TPMFIDO_PROMPTER_TEST") == "" {
		t.Skip("set TPMFIDO_PROMPTER_TEST to run against a system prompter")
	}
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// start the activatable prompter
	conn.BusObject().Call("org.freedesktop.DBus.StartServiceByName", 0, prompterBusName, uint32(0))
	if !SystemPrompterAvailable(conn) {
		t.Fatal("no system prompter")
	}
	p := NewPrompter(conn)

	prompt := ui.Prompt{
		Heading: "Sign In to example.com?",
		Body:    "example.com wants to confirm it’s you using the security key in this computer.",
		OK:      "Sign In",
	}
	answer := func(key string, screenshot string) {
		out, err := exec.Command("xdotool", "search", "--sync", "--name", prompt.Heading).Output()
		if err != nil {
			t.Errorf("dialog not found: %v", err)
			return
		}
		time.Sleep(500 * time.Millisecond)
		if screenshot != "" {
			exec.Command("import", "-window", "root", screenshot).Run()
		}
		win := string(out[:len(out)-1])
		// Xvfb has no window manager to activate windows, and GTK ignores
		// synthetic events sent with --window, so focus the window and
		// send real key events.
		exec.Command("xdotool", "windowfocus", "--sync", win).Run()
		exec.Command("xdotool", "key", key).Run()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	go answer("Return", os.Getenv("TPMFIDO_SCREENSHOT"))
	ok, err := p.Confirm(ctx, prompt)
	if err != nil || !ok {
		t.Fatalf("confirm: %v %v", ok, err)
	}

	go answer("Escape", "")
	ok, err = p.Confirm(ctx, prompt)
	if err != nil || ok {
		t.Fatalf("cancel: %v %v", ok, err)
	}

	// another client on the bus must not be able to answer the prompt
	other, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	forged := make(chan error, 1)
	go func() {
		exec.Command("xdotool", "search", "--sync", "--name", prompt.Heading).Run()
		path := dbus.ObjectPath(callbackPathPrefix + "/3")
		forged <- other.Object(conn.Names()[0], path).Call(callbackInterface+".PromptReady", 0,
			"yes", map[string]dbus.Variant{}, "").Err
	}()
	short, cancelShort := context.WithTimeout(ctx, 3*time.Second)
	defer cancelShort()
	ok, err = p.Confirm(short, prompt)
	if ferr := <-forged; ferr == nil {
		t.Error("forged PromptReady was accepted")
	}
	if ok || err != context.DeadlineExceeded {
		t.Fatalf("forged reply changed the result: %v %v", ok, err)
	}

	// the cancelled prompt must have been closed
	time.Sleep(time.Second)
	if exec.Command("xdotool", "search", "--name", prompt.Heading).Run() == nil {
		t.Fatal("dialog still shown after the request was cancelled")
	}
}
