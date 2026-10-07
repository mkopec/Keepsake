package ctap2

import "github.com/fxamacker/cbor/v2"

// authenticatorCredentialManagement (CTAP 2.1 section 6.8). The preview
// command of FIDO_2_1_PRE authenticators uses the same messages.
const (
	CmdCredentialMgmt        = 0x0A
	CmdCredentialMgmtPreview = 0x41

	CredMgmtGetCredsMetadata      = 0x01
	CredMgmtEnumerateRPsBegin     = 0x02
	CredMgmtEnumerateRPsNext      = 0x03
	CredMgmtEnumerateCredsBegin   = 0x04
	CredMgmtEnumerateCredsNext    = 0x05
	CredMgmtDeleteCredential      = 0x06
	CredMgmtUpdateUserInformation = 0x07
)

type CredMgmtReq struct {
	SubCommand uint `cbor:"1,keyasint"`
	// kept encoded: pinUvAuthParam is computed over the encoding
	SubCommandParams  cbor.RawMessage `cbor:"2,keyasint"`
	PinUvAuthProtocol uint            `cbor:"3,keyasint"`
	PinUvAuthParam    []byte          `cbor:"4,keyasint"`
}

type CredMgmtParams struct {
	RPIDHash     []byte                `cbor:"1,keyasint"`
	CredentialID *CredentialDescriptor `cbor:"2,keyasint"`
	User         *User                 `cbor:"3,keyasint"`
}

type CredMgmtResp struct {
	ExistingResidentCredentialsCount             *int                  `cbor:"1,keyasint,omitempty"`
	MaxPossibleRemainingResidentCredentialsCount *int                  `cbor:"2,keyasint,omitempty"`
	RP                                           *RelyingParty         `cbor:"3,keyasint,omitempty"`
	RPIDHash                                     []byte                `cbor:"4,keyasint,omitempty"`
	TotalRPs                                     int                   `cbor:"5,keyasint,omitempty"`
	User                                         *User                 `cbor:"6,keyasint,omitempty"`
	CredentialID                                 *CredentialDescriptor `cbor:"7,keyasint,omitempty"`
	PublicKey                                    cbor.RawMessage       `cbor:"8,keyasint,omitempty"`
	TotalCredentials                             int                   `cbor:"9,keyasint,omitempty"`
}
