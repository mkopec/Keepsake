// ui shows confirmation dialogs through a Confirmer backend (the GNOME
// system prompter or pinentry), one at a time.
package ui

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Prompt is the content of a confirmation dialog: a heading asking the
// question, a body sentence, and a Cancel and a confirming button.
type Prompt struct {
	Heading string
	Body    string
	// OK labels the confirming button. GNOME's HIG asks for a verb
	// describing the action ("Sign In"), not "OK".
	OK string
}

// Confirmer shows a confirmation dialog.
type Confirmer interface {
	// Confirm blocks until the user answers or ctx is done. It returns
	// true if the user confirmed.
	Confirm(ctx context.Context, p Prompt) (bool, error)
}

// PasswordPrompt is the content of a password or PIN dialog.
type PasswordPrompt struct {
	Prompt
	// Warning is shown in the dialog, e.g. after a wrong password.
	Warning string
}

// PasswordAsker is implemented by Confirmers that can also ask for a
// password.
type PasswordAsker interface {
	// Password blocks until the user answers or ctx is done. It returns
	// ErrCancelled if the user cancels.
	Password(ctx context.Context, p PasswordPrompt) (string, error)
}

// ErrCancelled is returned by Password when the user cancels the dialog.
var ErrCancelled = errors.New("dialog cancelled")

// ErrUnsupported is returned by Password when the dialog backend can't ask
// for passwords.
var ErrUnsupported = errors.New("dialog backend can't ask for passwords")

// ErrRateLimited is returned when Allow refuses a new dialog.
var ErrRateLimited = errors.New("too many dialogs")

// ErrBusy is returned when another dialog is already shown.
var ErrBusy = errors.New("other request already in progress")

func New(c Confirmer) *Prompter {
	return &Prompter{c: c}
}

// Prompter shows at most one dialog at a time.
type Prompter struct {
	c Confirmer

	// Allow, if set, is called before a new dialog is shown; if it
	// returns false the dialog isn't shown and ErrRateLimited returned.
	Allow func() bool

	mu     sync.Mutex
	busy   bool
	polled *polledRequest
}

// Confirm shows a dialog and blocks until the user answers or ctx is done.
// It is meant for CTAP2 requests, where the host waits for a single
// request.
func (p *Prompter) Confirm(ctx context.Context, prompt Prompt) (bool, error) {
	p.mu.Lock()
	if p.busy {
		p.mu.Unlock()
		return false, ErrBusy
	}
	if p.Allow != nil && !p.Allow() {
		p.mu.Unlock()
		return false, ErrRateLimited
	}
	p.busy = true
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		p.busy = false
		p.mu.Unlock()
	}()

	ok, err := p.c.Confirm(ctx, prompt)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return ok, err
}

// Password shows a password dialog and blocks until the user answers or ctx
// is done.
func (p *Prompter) Password(ctx context.Context, prompt PasswordPrompt) (string, error) {
	asker, ok := p.c.(PasswordAsker)
	if !ok {
		return "", ErrUnsupported
	}
	p.mu.Lock()
	if p.busy {
		p.mu.Unlock()
		return "", ErrBusy
	}
	if p.Allow != nil && !p.Allow() {
		p.mu.Unlock()
		return "", ErrRateLimited
	}
	p.busy = true
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		p.busy = false
		p.mu.Unlock()
	}()

	secret, err := asker.Password(ctx, prompt)
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return secret, err
}

type Result struct {
	OK    bool
	Error error
}

// polledRequest is a dialog for U2F requests, which hosts repeat about
// every 750ms until the user confirms.
type polledRequest struct {
	key           [64]byte
	pendingResult chan Result
	extendTimeout chan time.Duration
}

// pollTimeout is how long a U2F dialog stays open without the host
// repeating the request.
const pollTimeout = 2 * time.Second

// ConfirmPresence shows a dialog for a U2F request. Repeated requests with
// the same parameters return the pending result of the dialog that is
// already shown, which is closed once the host stops repeating the request.
func (p *Prompter) ConfirmPresence(prompt Prompt, challengeParam, applicationParam [32]byte) (chan Result, error) {
	var key [64]byte
	copy(key[:32], challengeParam[:])
	copy(key[32:], applicationParam[:])

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.polled != nil && p.polled.key == key {
		extend := p.polled.extendTimeout
		go func() {
			select {
			case extend <- pollTimeout:
			case <-time.After(pollTimeout):
			}
		}()
		return p.polled.pendingResult, nil
	}
	if p.busy {
		return nil, ErrBusy
	}
	if p.Allow != nil && !p.Allow() {
		return nil, ErrRateLimited
	}

	req := &polledRequest{
		key:           key,
		pendingResult: make(chan Result),
		extendTimeout: make(chan time.Duration),
	}
	p.busy = true
	p.polled = req
	go p.runPolled(req, prompt)

	return req.pendingResult, nil
}

func (p *Prompter) runPolled(req *polledRequest, prompt Prompt) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan Result, 1)
	go func() {
		ok, err := p.c.Confirm(ctx, prompt)
		result <- Result{OK: ok, Error: err}
	}()

	var r Result
	timer := time.NewTimer(pollTimeout)
wait:
	for {
		select {
		case r = <-result:
			break wait
		case <-timer.C:
			// The host stopped repeating the request, it is likely gone.
			cancel()
			<-result
			r = Result{Error: errors.New("request timed out")}
			break wait
		case d := <-req.extendTimeout:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		}
	}

	select {
	case req.pendingResult <- r:
	case <-time.After(pollTimeout):
	}

	p.mu.Lock()
	p.busy = false
	p.polled = nil
	p.mu.Unlock()
}
