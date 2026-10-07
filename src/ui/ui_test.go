package ui

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConfirmer answers after delay, or blocks until ctx is done if
// delay is negative.
type fakeConfirmer struct {
	delay  time.Duration
	answer bool
	calls  atomic.Int32
}

func (f *fakeConfirmer) Confirm(ctx context.Context, p Prompt) (bool, error) {
	f.calls.Add(1)
	if f.delay < 0 {
		<-ctx.Done()
		return false, ctx.Err()
	}
	select {
	case <-time.After(f.delay):
		return f.answer, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func TestConfirmBusy(t *testing.T) {
	p := New(&fakeConfirmer{delay: -1})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Confirm(ctx, Prompt{})
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)

	if _, err := p.Confirm(context.Background(), Prompt{}); err != ErrBusy {
		t.Fatalf("second dialog: %v", err)
	}
	cancel()
	<-done
	if _, err := p.Confirm(ctx, Prompt{}); err != context.Canceled {
		t.Fatalf("cancelled ctx: %v", err)
	}
}

func TestConfirmPresencePolling(t *testing.T) {
	f := &fakeConfirmer{delay: 300 * time.Millisecond, answer: true}
	p := New(f)
	var c, a [32]byte
	a[0] = 1

	ch1, err := p.ConfirmPresence(Prompt{}, c, a)
	if err != nil {
		t.Fatal(err)
	}
	ch2, err := p.ConfirmPresence(Prompt{}, c, a)
	if err != nil || ch2 != ch1 {
		t.Fatalf("repeated request didn't join the pending dialog: %v", err)
	}
	if _, err := p.ConfirmPresence(Prompt{}, c, [32]byte{2}); err != ErrBusy {
		t.Fatalf("different request: %v", err)
	}
	if _, err := p.Confirm(context.Background(), Prompt{}); err != ErrBusy {
		t.Fatalf("CTAP2 dialog during U2F dialog: %v", err)
	}
	if r := <-ch1; !r.OK {
		t.Fatalf("result %+v", r)
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("%d dialogs shown", n)
	}
	time.Sleep(10 * time.Millisecond)
	if ok, err := p.Confirm(context.Background(), Prompt{}); !ok || err != nil {
		t.Fatalf("dialog after U2F dialog: %v %v", ok, err)
	}
}

func TestConfirmPresenceAbandoned(t *testing.T) {
	p := New(&fakeConfirmer{delay: -1})
	ch, err := p.ConfirmPresence(Prompt{}, [32]byte{}, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-ch:
		if r.OK || r.Error == nil {
			t.Fatalf("result %+v", r)
		}
	case <-time.After(3 * pollTimeout):
		t.Fatal("abandoned dialog wasn't closed")
	}
}

func TestAllow(t *testing.T) {
	p := New(&fakeConfirmer{answer: true})
	allowed := false
	p.Allow = func() bool { return allowed }
	if _, err := p.Confirm(context.Background(), Prompt{}); err != ErrRateLimited {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := p.ConfirmPresence(Prompt{}, [32]byte{}, [32]byte{}); err != ErrRateLimited {
		t.Fatalf("U2F: %v", err)
	}
	allowed = true
	if ok, err := p.Confirm(context.Background(), Prompt{}); !ok || err != nil {
		t.Fatalf("allowed: %v %v", ok, err)
	}
}
