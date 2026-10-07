package pinentry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
)

func New() *Pinentry {
	return &Pinentry{}
}

type Pinentry struct {
	mu            sync.Mutex
	activeRequest *request
}

type request struct {
	timeout       time.Duration
	pendingResult chan Result
	extendTimeout chan time.Duration

	challengeParam   [32]byte
	applicationParam [32]byte
}

// Prompt is the content of a confirmation dialog. pinentry-gnome3 shows it
// as a GNOME Shell system prompt: Heading as the bold heading, Body below
// it, and a Cancel and an OK button. Other pinentries don't show the
// heading of a confirmation, so it is also used as the window title.
type Prompt struct {
	Heading string
	Body    string
	// OK labels the confirming button. GNOME's HIG asks for a verb
	// describing the action ("Sign In"), not "OK".
	OK string
}

func (p Prompt) apply(c *pinentry.Client) {
	c.SetTitle(p.Heading)
	c.SetPrompt(p.Heading)
	c.SetDesc(p.Body)
	if p.OK != "" {
		c.SetOkBtn(p.OK)
	}
	c.SetCancelBtn("Cancel")
}

type Result struct {
	OK    bool
	Error error
}

func (pe *Pinentry) ConfirmPresence(prompt Prompt, challengeParam, applicationParam [32]byte) (chan Result, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	timeout := 2 * time.Second

	if pe.activeRequest != nil {
		if challengeParam != pe.activeRequest.challengeParam || applicationParam != pe.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		extendTimeoutChan := pe.activeRequest.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(timeout):
			}
		}()

		return pe.activeRequest.pendingResult, nil
	}

	pe.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
		extendTimeout:    make(chan time.Duration),
	}

	go pe.prompt(pe.activeRequest, prompt)

	return pe.activeRequest.pendingResult, nil
}

// Confirm shows a confirmation dialog and blocks
// until the user answers or ctx is done. It returns true if the user
// confirmed. Unlike ConfirmPresence it is meant for CTAP2 requests, where the
// host waits for a single request instead of polling.
func (pe *Pinentry) Confirm(ctx context.Context, prompt Prompt) (bool, error) {
	pe.mu.Lock()
	if pe.activeRequest != nil {
		pe.mu.Unlock()
		return false, errors.New("other request already in progress")
	}
	pe.activeRequest = &request{}
	pe.mu.Unlock()

	defer func() {
		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()
	}()

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
	prompt.apply(p)

	promptResult := make(chan error, 1)
	go func() {
		promptResult <- p.Confirm()
	}()

	select {
	case err := <-promptResult:
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return err == nil, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (pe *Pinentry) prompt(req *request, prompt Prompt) {
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(req.timeout):
			// we expect requests to come in every ~750ms.
			// If we've been waiting for 2 seconds the client
			// is likely gone.
		}

		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()
	}

	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, cmd, err := launchPinEntry(childCtx)
	if err != nil {
		sendResult(Result{
			OK:    false,
			Error: fmt.Errorf("failed to start pinentry: %w", err),
		})
		return
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	prompt.apply(p)

	promptResult := make(chan bool)

	go func() {
		err := p.Confirm()
		promptResult <- err == nil
	}()

	timer := time.NewTimer(req.timeout)

	for {
		select {
		case ok := <-promptResult:
			sendResult(Result{
				OK: ok,
			})
			return
		case <-timer.C:
			sendResult(Result{
				OK:    false,
				Error: errors.New("request timed out"),
			})
			return
		case d := <-req.extendTimeout:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		}
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
