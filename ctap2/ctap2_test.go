package ctap2

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestCOSEKeyCanonicalOrder(t *testing.T) {
	x := big.NewInt(1)
	y := big.NewInt(2)
	got, err := COSEKeyES256(x, y)
	if err != nil {
		t.Fatal(err)
	}

	// {1: 2, 3: -7, -1: 1, -2: x, -3: y}
	want := "a5" + "0102" + "0326" + "2001" +
		"215820" + hex.EncodeToString(x.FillBytes(make([]byte, 32))) +
		"225820" + hex.EncodeToString(y.FillBytes(make([]byte, 32)))
	if hex.EncodeToString(got) != want {
		t.Fatalf("got  %x\nwant %s", got, want)
	}
}

func TestCredentialDescriptorOrder(t *testing.T) {
	got, err := Marshal(CredentialDescriptor{Type: CredentialTypePublic, ID: []byte{0xaa}})
	if err != nil {
		t.Fatal(err)
	}
	// {"id": h'aa', "type": "public-key"}: shorter key sorts first
	want, _ := hex.DecodeString("a2626964" + "41aa" + "6474797065" + "6a7075626c69632d6b6579")
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %x\nwant %x", got, want)
	}
}

func TestPinUvAuthParamPresence(t *testing.T) {
	// {1: "x", 2: h'', 6: h''}
	raw, _ := hex.DecodeString("a3" + "016178" + "0240" + "0640")
	var req GetAssertionReq
	if err := Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if req.PinUvAuthParam == nil || len(*req.PinUvAuthParam) != 0 {
		t.Fatalf("expected present, zero length pinUvAuthParam, got %v", req.PinUvAuthParam)
	}

	// {1: "x", 2: h''}
	raw, _ = hex.DecodeString("a2" + "016178" + "0240")
	req = GetAssertionReq{}
	if err := Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if req.PinUvAuthParam != nil {
		t.Fatalf("expected absent pinUvAuthParam")
	}
}

func TestUnmarshalInvalid(t *testing.T) {
	var req GetAssertionReq
	if err := Unmarshal([]byte{0xa1, 0x01}, &req); err != ErrInvalidCBOR {
		t.Fatalf("expected ErrInvalidCBOR, got %v", err)
	}
}
