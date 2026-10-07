package tpm

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestParseSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, seedSizeBytes)
	v2 := func(o KeyOptions) keyHandleFlags { return keyHandleFlags{KeyOptions: o, format: keyHandleFormatV2} }
	v3 := func(o KeyOptions) keyHandleFlags {
		return keyHandleFlags{KeyOptions: o, format: keyHandleFormat, credAuth: true}
	}
	cases := []struct {
		field []byte
		want  keyHandleFlags
	}{
		{seed, keyHandleFlags{legacy: true}},
		{append([]byte{0x20}, seed...), v2(KeyOptions{CredProtect: 1})},
		{append([]byte{0x2b}, seed...), v2(KeyOptions{HMACSecret: true, Discoverable: true, CredProtect: 3})},
		{append([]byte{0x30}, seed...), v3(KeyOptions{CredProtect: 1})},
		{append([]byte{0x31}, seed...), v3(KeyOptions{HMACSecret: true, CredProtect: 1})},
		{append([]byte{0x36}, seed...), v3(KeyOptions{Discoverable: true, CredProtect: 2})},
		{append([]byte{0x3b}, seed...), v3(KeyOptions{HMACSecret: true, Discoverable: true, CredProtect: 3})},
	}
	for _, c := range cases {
		got, f, err := parseSeed(c.field)
		if err != nil || f != c.want || !bytes.Equal(got, seed) {
			t.Fatalf("seed %x: got %x %+v %v", c.field, got, f, err)
		}
		if !f.legacy && f.versionByte() != c.field[0] {
			t.Fatalf("versionByte %x != %x", f.versionByte(), c.field[0])
		}
	}

	// 0x1X didn't authenticate the flags and is no longer accepted; 0x3c
	// has both credProtect flags
	for _, bad := range [][]byte{nil, seed[:19], append([]byte{0x01}, seed...), append([]byte{0x12}, seed...),
		append([]byte{0x3c}, seed...), append([]byte{0x40}, seed...), append(seed, 1, 2)} {
		if _, _, err := parseSeed(bad); err == nil {
			t.Errorf("accepted invalid seed %x", bad)
		}
	}
}

// The primary template of legacy key handles must encode exactly as the
// legacy go-tpm API did.
func TestPrimaryTemplateMatchesLegacy(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, seedSizeBytes)
	app := bytes.Repeat([]byte{9}, 32)
	for _, noDA := range []bool{false, true} {
		got := tpm2.Marshal(primaryTemplate(seed, app, noDA))
		want, err := legacyPrimaryTemplate(seed, app, noDA).Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("noDA=%v:\ngot  %x\nwant %x", noDA, got, want)
		}
	}
}

func TestPinPolicyDependsOnUVKey(t *testing.T) {
	a, _ := pinPolicy(tpm2.TPM2BName{Buffer: []byte{0, 0x0b, 1}})
	b, _ := pinPolicy(tpm2.TPM2BName{Buffer: []byte{0, 0x0b, 2}})
	if len(a) != 32 || bytes.Equal(a, b) {
		t.Fatalf("policies %x %x", a, b)
	}
}

func TestUVKeyBlobRoundTrip(t *testing.T) {
	priv := tpm2.TPM2BPrivate{Buffer: bytes.Repeat([]byte{1}, 150)}
	pub := bytes.Repeat([]byte{2}, 50)
	blob, err := encodeUVKeyBlob(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	gotPriv, gotPub, err := decodeUVKeyBlob(blob)
	if err != nil || !bytes.Equal(gotPriv.Buffer, priv.Buffer) || !bytes.Equal(gotPub.Bytes(), pub) {
		t.Fatalf("round trip failed: %v", err)
	}

	for _, bad := range [][]byte{nil, blob[:10], append(blob, 0)} {
		if _, _, err := decodeUVKeyBlob(bad); err == nil {
			t.Errorf("accepted invalid blob of %d bytes", len(bad))
		}
	}
	if _, err := encodeUVKeyBlob(tpm2.TPM2BPrivate{Buffer: make([]byte, maxUVKeyBlobSize)}, pub); err == nil {
		t.Error("accepted oversized blob")
	}
}
