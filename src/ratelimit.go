package main

import (
	"flag"
	"log"
	"sync"
	"time"
)

// Any program that can open the device (or use the session bus) can make
// Keepsake show dialogs. dialogLimiter refuses requests that would show
// more than dialogBurst dialogs within dialogWindow, so such a program
// can't flood the screen (or make the user click through out of
// annoyance).
var dialogBurst = flag.Int("dialog-limit", 6, "dialogs allowed within 30 seconds; 0 disables the limit")

const dialogWindow = 30 * time.Second

type dialogLimiter struct {
	mu     sync.Mutex
	shown  []time.Time
	logged time.Time
}

// allow records a dialog and reports whether it may be shown.
func (l *dialogLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	recent := l.shown[:0]
	for _, t := range l.shown {
		if now.Sub(t) < dialogWindow {
			recent = append(recent, t)
		}
	}
	l.shown = recent
	if *dialogBurst > 0 && len(l.shown) >= *dialogBurst {
		if now.Sub(l.logged) > dialogWindow {
			log.Printf("too many confirmation requests, refusing them for a while")
			l.logged = now
		}
		return false
	}
	l.shown = append(l.shown, now)
	return true
}
