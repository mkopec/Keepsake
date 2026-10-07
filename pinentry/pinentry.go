package pinentry

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
	"github.com/psanford/tpm-fido/ui"
)

func New() *Pinentry {
	return &Pinentry{}
}

// Pinentry shows confirmation dialogs with a pinentry program. It
// implements ui.Confirmer.
type Pinentry struct{}

// The heading is set as the prompt, which pinentry-gnome3 shows as the
// heading of the GNOME Shell system prompt. Other pinentries don't show
// the prompt of a confirmation, so it is also used as the window title.
func apply(c *pinentry.Client, p ui.Prompt) {
	c.SetTitle(p.Heading)
	c.SetPrompt(p.Heading)
	c.SetDesc(p.Body)
	if p.OK != "" {
		c.SetOkBtn(p.OK)
	}
	c.SetCancelBtn("Cancel")
}

// Confirm shows a confirmation dialog and blocks until the user answers or
// ctx is done.
func (pe *Pinentry) Confirm(ctx context.Context, prompt ui.Prompt) (bool, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	p, cmd, err := launchPinEntry(childCtx)
	if err != nil {
		return false, fmt.Errorf("failed to start pinentry: %w", err)
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	apply(p, prompt)

	promptResult := make(chan error, 1)
	go func() {
		promptResult <- p.Confirm()
	}()

	select {
	case err := <-promptResult:
		return err == nil, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// Password asks for a password with pinentry's GETPIN.
func (pe *Pinentry) Password(ctx context.Context, prompt ui.PasswordPrompt) (string, error) {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	p, cmd, err := launchPinEntry(childCtx)
	if err != nil {
		return "", fmt.Errorf("failed to start pinentry: %w", err)
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	apply(p, prompt.Prompt)
	if prompt.Warning != "" {
		p.SetError(prompt.Warning)
	}

	type result struct {
		pin string
		err error
	}
	res := make(chan result, 1)
	go func() {
		pin, err := p.GetPIN()
		res <- result{pin, err}
	}()

	select {
	case r := <-res:
		if r.err != nil {
			// pinentry answers a cancelled dialog with an error
			return "", ui.ErrCancelled
		}
		return r.pin, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func FindPinentryGUIPath() string {
	candidates := []string{
		"pinentry-gnome3",
		"pinentry-qt5",
		"pinentry-qt4",
		"pinentry-qt",
		"pinentry-gtk-2",
		"pinentry-x11",
		"pinentry-fltk",
	}
	for _, candidate := range candidates {
		p, _ := exec.LookPath(candidate)
		if p != "" {
			return p
		}
	}
	return ""
}

func launchPinEntry(ctx context.Context) (*pinentry.Client, *exec.Cmd, error) {
	pinEntryCmd := FindPinentryGUIPath()
	if pinEntryCmd == "" {
		log.Printf("Failed to detect gui pinentry binary. Falling back to default `pinentry`")
		pinEntryCmd = "pinentry"
	}
	cmd := exec.CommandContext(ctx, pinEntryCmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	var c pinentry.Client
	c.Session, err = assuan.Init(assuan.ReadWriteCloser{
		ReadCloser:  stdout,
		WriteCloser: stdin,
	})

	if err != nil {
		return nil, nil, err
	}
	return &c, cmd, nil
}
