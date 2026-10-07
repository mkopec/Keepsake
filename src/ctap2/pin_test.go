package ctap2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestPINProtocolRoundTrip(t *testing.T) {
	for _, v := range []uint{1, 2} {
		p := LookupPINProtocol(v)

		auth, _ := ecdh.P256().GenerateKey(rand.Reader)
		platform, _ := ecdh.P256().GenerateKey(rand.Reader)

		// the platform's key travels as a COSE key
		pub, err := KeyAgreementCOSEKey(platform.PublicKey()).ECDHPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		z1, _ := auth.ECDH(pub)
		z2, _ := platform.ECDH(auth.PublicKey())
		s1, s2 := p.SharedSecret(z1), p.SharedSecret(z2)
		if !bytes.Equal(s1, s2) {
			t.Fatalf("v%d: shared secrets differ", v)
		}

		msg := bytes.Repeat([]byte{0x42}, 64)
		ct := p.Encrypt(s1, msg)
		pt, err := p.Decrypt(s2, ct)
		if err != nil || !bytes.Equal(pt, msg) {
			t.Fatalf("v%d: decrypt mismatch: %v", v, err)
		}

		mac := p.Authenticate(s1, msg)
		if !VerifyPINAuth(p, s2, msg, mac) {
			t.Fatalf("v%d: mac doesn't verify", v)
		}
		mac[0] ^= 1
		if VerifyPINAuth(p, s2, msg, mac) {
			t.Fatalf("v%d: corrupted mac verifies", v)
		}
	}
}

func TestPINProtocolSizes(t *testing.T) {
	key := make([]byte, 64)
	if n := len(LookupPINProtocol(1).Authenticate(key[:32], nil)); n != 16 {
		t.Fatalf("v1 mac size %d", n)
	}
	if n := len(LookupPINProtocol(2).Authenticate(key, nil)); n != 32 {
		t.Fatalf("v2 mac size %d", n)
	}
	if n := len(LookupPINProtocol(2).Encrypt(key, make([]byte, 16))); n != 32 {
		t.Fatalf("v2 ciphertext should include IV, got %d", n)
	}
	if _, err := LookupPINProtocol(1).Decrypt(key[:32], make([]byte, 15)); err != ErrInvalidParameter {
		t.Fatalf("v1 short ciphertext: %v", err)
	}
	if _, err := LookupPINProtocol(2).Decrypt(key, make([]byte, 16)); err != ErrInvalidParameter {
		t.Fatalf("v2 ciphertext without data: %v", err)
	}
	if LookupPINProtocol(3) != nil {
		t.Fatal("protocol 3 shouldn't exist")
	}
}

func TestECDHPublicKeyRejectsInvalidPoint(t *testing.T) {
	k := &COSEKey{Kty: 2, Crv: 1, X: make([]byte, 32), Y: make([]byte, 32)}
	if _, err := k.ECDHPublicKey(); err != ErrInvalidParameter {
		t.Fatalf("expected ErrInvalidParameter, got %v", err)
	}
}
