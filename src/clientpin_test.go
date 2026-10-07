package main

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/psanford/tpm-fido/src/ctap2"
)

func TestDecryptNewPIN(t *testing.T) {
	p := ctap2.LookupPINProtocol(2)
	key := make([]byte, 64)

	pad := func(pin string, n int) []byte {
		b := make([]byte, n)
		copy(b, pin)
		return b
	}

	h := sha256.Sum256([]byte("1234"))
	got, err := decryptNewPIN(p, key, p.Encrypt(key, pad("1234", 64)))
	if err != nil || string(got) != string(h[:16]) {
		t.Fatalf("valid PIN: %x %v", got, err)
	}

	cases := []struct {
		name string
		pin  []byte
		want error
	}{
		{"too short", pad("123", 64), ctap2.ErrPinPolicyViolation},
		{"4 runes, 8 bytes", pad("ąęść", 64), nil},
		{"no zero padding", []byte(strings.Repeat("1", 64)), ctap2.ErrPinPolicyViolation},
		{"invalid utf-8", pad("\xff\xfe\xfd\xfc", 64), ctap2.ErrPinPolicyViolation},
		{"wrong padded size", pad("1234", 48), ctap2.ErrInvalidParameter},
	}
	for _, c := range cases {
		_, err := decryptNewPIN(p, key, p.Encrypt(key, c.pin))
		if err != c.want {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}
