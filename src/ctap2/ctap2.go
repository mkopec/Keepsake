// ctap2 implements the CBOR message encoding of the FIDO2 Client to
// Authenticator Protocol (CTAP 2.0).
//
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
package ctap2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// Command bytes (section 5)
const (
	CmdMakeCredential    = 0x01
	CmdGetAssertion      = 0x02
	CmdGetInfo           = 0x04
	CmdClientPIN         = 0x06
	CmdReset             = 0x07
	CmdGetNextAssertion  = 0x08
	CmdSelection         = 0x0B
	CredentialTypePublic = "public-key"

	// COSE algorithm identifier for ECDSA w/ SHA-256 on P-256
	AlgES256 = -7
)

// Status is a CTAP2 status code (section 6.3). It implements error so that
// command handlers can return it directly.
type Status byte

const (
	StatusOK                Status = 0x00
	ErrInvalidCommand       Status = 0x01
	ErrInvalidParameter     Status = 0x02
	ErrInvalidLength        Status = 0x03
	ErrInvalidCBOR          Status = 0x12
	ErrInvalidSubcommand    Status = 0x3E
	ErrMissingParameter     Status = 0x14
	ErrCredentialExcluded   Status = 0x19
	ErrUnsupportedAlgorithm Status = 0x26
	ErrOperationDenied      Status = 0x27
	ErrKeyStoreFull         Status = 0x28
	ErrUnsupportedOption    Status = 0x2B
	ErrInvalidOption        Status = 0x2C
	ErrKeepaliveCancel      Status = 0x2D
	ErrNoCredentials        Status = 0x2E
	ErrUserActionTimeout    Status = 0x2F
	ErrNotAllowed           Status = 0x30
	ErrPinInvalid           Status = 0x31
	ErrPinBlocked           Status = 0x32
	ErrPinAuthInvalid       Status = 0x33
	ErrPinAuthBlocked       Status = 0x34
	ErrPinNotSet            Status = 0x35
	ErrPinRequired          Status = 0x36
	ErrPinPolicyViolation   Status = 0x37
	ErrOther                Status = 0x7F
)

func (s Status) Error() string {
	return fmt.Sprintf("ctap2 status 0x%02x", byte(s))
}

// authenticatorData flags (WebAuthn section 6.1)
const (
	FlagUserPresent            = 0x01
	FlagUserVerified           = 0x04
	FlagAttestedCredentialData = 0x40
	FlagExtensionData          = 0x80
)

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	encMode, err = cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decMode, err = cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// Marshal encodes v using the CTAP2 canonical CBOR encoding.
func Marshal(v interface{}) ([]byte, error) {
	return encMode.Marshal(v)
}

// Unmarshal decodes a CTAP2 request parameter map into v.
func Unmarshal(data []byte, v interface{}) error {
	if err := decMode.Unmarshal(data, v); err != nil {
		return ErrInvalidCBOR
	}
	return nil
}

// Extensions maps extension identifiers to their undecoded CBOR inputs.
type Extensions = map[string]cbor.RawMessage

type RelyingParty struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
	Icon string `cbor:"icon,omitempty"`
}

type User struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
	Icon        string `cbor:"icon,omitempty"`
}

type CredentialParameter struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}

type CredentialDescriptor struct {
	Type       string   `cbor:"type"`
	ID         []byte   `cbor:"id"`
	Transports []string `cbor:"transports,omitempty"`
}

type MakeCredentialReq struct {
	ClientDataHash    []byte                 `cbor:"1,keyasint"`
	RP                *RelyingParty          `cbor:"2,keyasint"`
	User              *User                  `cbor:"3,keyasint"`
	PubKeyCredParams  []CredentialParameter  `cbor:"4,keyasint"`
	ExcludeList       []CredentialDescriptor `cbor:"5,keyasint"`
	Extensions        Extensions             `cbor:"6,keyasint"`
	Options           map[string]bool        `cbor:"7,keyasint"`
	PinUvAuthParam    *[]byte                `cbor:"8,keyasint"`
	PinUvAuthProtocol uint                   `cbor:"9,keyasint"`
}

type GetAssertionReq struct {
	RPID              string                 `cbor:"1,keyasint"`
	ClientDataHash    []byte                 `cbor:"2,keyasint"`
	AllowList         []CredentialDescriptor `cbor:"3,keyasint"`
	Extensions        Extensions             `cbor:"4,keyasint"`
	Options           map[string]bool        `cbor:"5,keyasint"`
	PinUvAuthParam    *[]byte                `cbor:"6,keyasint"`
	PinUvAuthProtocol uint                   `cbor:"7,keyasint"`
}

type GetInfoResp struct {
	Versions     []string        `cbor:"1,keyasint"`
	Extensions   []string        `cbor:"2,keyasint,omitempty"`
	AAGUID       []byte          `cbor:"3,keyasint"`
	Options      map[string]bool `cbor:"4,keyasint,omitempty"`
	MaxMsgSize   uint            `cbor:"5,keyasint,omitempty"`
	PinProtocols []uint          `cbor:"6,keyasint,omitempty"`
}

// PackedAttStmt is a "packed" attestation statement. Without x5c it is a
// self attestation: the signature is made with the credential key itself.
type PackedAttStmt struct {
	Alg int    `cbor:"alg"`
	Sig []byte `cbor:"sig"`
}

type MakeCredentialResp struct {
	Fmt      string        `cbor:"1,keyasint"`
	AuthData []byte        `cbor:"2,keyasint"`
	AttStmt  PackedAttStmt `cbor:"3,keyasint"`
}

type GetAssertionResp struct {
	Credential          CredentialDescriptor `cbor:"1,keyasint"`
	AuthData            []byte               `cbor:"2,keyasint"`
	Signature           []byte               `cbor:"3,keyasint"`
	User                *User                `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials int                  `cbor:"5,keyasint,omitempty"`
}

// COSEKeyES256 encodes a P-256 public key as a COSE_Key.
func COSEKeyES256(x, y *big.Int) ([]byte, error) {
	return Marshal(COSEKey{
		Kty: 2, // EC2
		Alg: AlgES256,
		Crv: 1, // P-256
		X:   x.FillBytes(make([]byte, 32)),
		Y:   y.FillBytes(make([]byte, 32)),
	})
}

// AuthenticatorData builds the WebAuthn authenticatorData structure.
// attestedCredData and extensions (a CBOR map) may be nil.
func AuthenticatorData(rpIDHash []byte, flags byte, signCount uint32, attestedCredData, extensions []byte) []byte {
	var buf bytes.Buffer
	buf.Write(rpIDHash)
	if attestedCredData != nil {
		flags |= FlagAttestedCredentialData
	}
	if extensions != nil {
		flags |= FlagExtensionData
	}
	buf.WriteByte(flags)
	binary.Write(&buf, binary.BigEndian, signCount)
	buf.Write(attestedCredData)
	buf.Write(extensions)
	return buf.Bytes()
}

// AttestedCredentialData builds the attestedCredentialData part of
// authenticatorData.
func AttestedCredentialData(aaguid, credID, coseKey []byte) []byte {
	var buf bytes.Buffer
	buf.Write(aaguid)
	binary.Write(&buf, binary.BigEndian, uint16(len(credID)))
	buf.Write(credID)
	buf.Write(coseKey)
	return buf.Bytes()
}
