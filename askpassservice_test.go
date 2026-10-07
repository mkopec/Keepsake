package main

import (
	"crypto/sha256"
	"testing"
	"time"
)

func pinHash(pin string) []byte {
	h := sha256.Sum256([]byte(pin))
	return h[:16]
}

func TestPresenceGrant(t *testing.T) {
	var g presenceGrant
	if g.consume(pinHash("1234")) {
		t.Fatal("grant without AskPIN")
	}

	g.set("1234")
	if g.consume(pinHash("9999")) {
		t.Fatal("grant for another PIN")
	}
	if g.consume(pinHash("1234")) {
		t.Fatal("a failed consume must remove the grant")
	}

	g.set("1234")
	if !g.consume(pinHash("1234")) {
		t.Fatal("grant not used")
	}
	if g.consume(pinHash("1234")) {
		t.Fatal("grant used twice")
	}

	g.set("1234")
	g.expires = time.Now().Add(-time.Second)
	if g.consume(pinHash("1234")) {
		t.Fatal("expired grant used")
	}

	g.set("1234")
	if g.consume(nil) {
		t.Fatal("grant used without a verified PIN")
	}
}

func TestUsePresenceGrantNeedsUV(t *testing.T) {
	s := &server{pin: newPINState()}
	s.pin.pinHash = pinHash("1234")
	s.grant.set("1234")
	if s.usePresenceGrant(false, "ssh:") {
		t.Fatal("grant used for a request without user verification")
	}
	s.grant.set("1234")
	if s.usePresenceGrant(true, "github.com") {
		t.Fatal("grant used for a website")
	}
	s.grant.set("1234")
	if !s.usePresenceGrant(true, "ssh:") {
		t.Fatal("grant not used")
	}
}

func TestSSHPINPrompt(t *testing.T) {
	p := sshPINPrompt("Enter PIN and confirm user presence for ECDSA-SK key SHA256:qMGHdoSbom6l8jUSedmcph3ZSB4jwjl7RdDdTFSybuE: ")
	if p.Body != "Enter the PIN of the security key in this computer to sign in with SSH key SHA256:qMGHdoSbom6l8jUSedmcph3ZSB4jwjl7RdDdTFSybuE." {
		t.Fatalf("body %q", p.Body)
	}
}

func TestPINTokenExpiry(t *testing.T) {
	ps := newPINState()
	ps.pinHash = pinHash("1234")
	held := ps.pinHash
	token := append([]byte(nil), ps.pinToken...)

	ps.tokenExpires = time.Now().Add(time.Minute)
	ps.expire()
	if ps.pinHash == nil {
		t.Fatal("expired too early")
	}

	ps.tokenExpires = time.Now().Add(-time.Second)
	ps.expire()
	if ps.pinHash != nil || string(ps.pinToken) == string(token) {
		t.Fatal("token not expired")
	}
	for _, b := range held {
		if b != 0 {
			t.Fatal("PIN hash not wiped from memory")
		}
	}
}
