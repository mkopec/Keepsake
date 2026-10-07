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

func TestAskpassToken(t *testing.T) {
	var g presenceGrant
	token := g.set("1234")
	if token == "1234" || len(token) < 4 || len(token) > 63 {
		t.Fatalf("bad token %q", token)
	}
	if g.resolve(pinHash("1234")) != nil {
		t.Fatal("the real PIN must not resolve")
	}
	real := g.resolve(pinHash(token))
	if string(real) != string(pinHash("1234")) {
		t.Fatal("token didn't resolve to the PIN")
	}
	if g.resolve(pinHash(token)) != nil {
		t.Fatal("token resolved twice")
	}
	// the presence grant is still there for the request that follows
	if !g.consume(pinHash("1234")) {
		t.Fatal("presence grant lost")
	}

	token = g.set("1234")
	g.expires = time.Now().Add(-time.Second)
	if g.resolve(pinHash(token)) != nil {
		t.Fatal("expired token resolved")
	}
}

func TestSSHOnlyPINToken(t *testing.T) {
	s := &server{pin: newPINState(), pins: alwaysPIN{}}
	s.pin.sshOnly = true
	cdh := make([]byte, 32)
	param := ctap2PINAuth(s.pin.pinToken, cdh)
	if _, err := s.checkPINUVAuth(&param, 2, cdh, false, "github.com"); err == nil {
		t.Fatal("ssh-only pinToken accepted for a website")
	}
	if uv, err := s.checkPINUVAuth(&param, 2, cdh, false, "ssh:"); !uv || err != nil {
		t.Fatalf("ssh: %v %v", uv, err)
	}
}
