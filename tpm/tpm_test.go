package tpm

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestParseSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, seedSizeBytes)
	cases := []struct {
		field []byte
		want  keyHandleFlags
	}{
		{seed, keyHandleFlags{legacy: true}},
		{append([]byte{0x10}, seed...), keyHandleFlags{}},
		{append([]byte{0x11}, seed...), keyHandleFlags{hmacSecret: true}},
		{append([]byte{0x12}, seed...), keyHandleFlags{discoverable: true}},
		{append([]byte{0x13}, seed...), keyHandleFlags{hmacSecret: true, discoverable: true}},
	}
	for _, c := range cases {
		got, flags, err := parseSeed(c.field)
		if err != nil || flags != c.want || !bytes.Equal(got, seed) {
			t.Fatalf("seed %x: got %x %+v %v", c.field, got, flags, err)
		}
		if !flags.legacy && flags.versionByte() != c.field[0] {
			t.Fatalf("versionByte %x != %x", flags.versionByte(), c.field[0])
		}
	}

	// 0x01 and 0x02 were used by unreleased versions before the device key
	for _, bad := range [][]byte{nil, seed[:19], append([]byte{0x01}, seed...), append([]byte{0x02}, seed...),
		append([]byte{0x14}, seed...), append([]byte{0x20}, seed...), append(seed, 1, 2)} {
		if _, _, err := parseSeed(bad); err == nil {
			t.Errorf("accepted invalid seed %x", bad)
		}
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
