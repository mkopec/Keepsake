package tpm

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestParseSeed(t *testing.T) {
	legacy := bytes.Repeat([]byte{7}, seedSizeBytes)
	cases := []struct {
		field []byte
		want  keyHandleFlags
	}{
		{legacy, keyHandleFlags{}},
		{append([]byte{keyHandleVersionNoDA}, legacy...), keyHandleFlags{noDA: true}},
		{append([]byte{keyHandleVersionHMACSecret}, legacy...), keyHandleFlags{noDA: true, hmacSecret: true}},
	}
	for _, c := range cases {
		seed, flags, err := parseSeed(c.field)
		if err != nil || flags != c.want || !bytes.Equal(seed, legacy) {
			t.Fatalf("seed %x: got %x %+v %v", c.field, seed, flags, err)
		}
	}

	for _, bad := range [][]byte{nil, legacy[:19], append([]byte{0x03}, legacy...), append(legacy, 1, 2)} {
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
