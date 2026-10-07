package main

import (
	"testing"
)

func TestDialogLimiter(t *testing.T) {
	var l dialogLimiter
	for i := 0; i < *dialogBurst; i++ {
		if !l.allow() {
			t.Fatalf("dialog %d refused", i)
		}
	}
	if l.allow() {
		t.Fatal("burst exceeded")
	}
	for i := range l.shown {
		l.shown[i] = l.shown[i].Add(-dialogWindow)
	}
	if !l.allow() {
		t.Fatal("not allowed after the window")
	}
}
