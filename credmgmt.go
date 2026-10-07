package main

import (
	"bytes"
	"crypto/sha256"
	"log"

	"github.com/psanford/tpm-fido/ctap2"
	"github.com/psanford/tpm-fido/passkeys"
)

// credMgmtState holds the remaining items of an enumeration.
type credMgmtState struct {
	// the CTAPHID channel that started the enumeration
	chanID uint32
	rps    []ctap2.RelyingParty
	creds  []passkeys.Credential
}

func (s *server) credentialManagement(chanID uint32, req *ctap2.CredMgmtReq) (interface{}, error) {
	log.Printf("got ctap2 CredentialManagement subcommand=0x%02x", req.SubCommand)

	// Only the *Next subcommands continue an enumeration.
	state := s.credMgmt
	if state != nil && state.chanID != chanID {
		// another channel's enumeration: leave it alone
		state = nil
	} else {
		s.credMgmt = nil
	}

	switch req.SubCommand {
	case ctap2.CredMgmtEnumerateRPsNext:
		if state == nil || len(state.rps) == 0 {
			return nil, ctap2.ErrNotAllowed
		}
		rp := state.rps[0]
		state.rps = state.rps[1:]
		s.credMgmt = state
		h := sha256.Sum256([]byte(rp.ID))
		return ctap2.CredMgmtResp{RP: &rp, RPIDHash: h[:]}, nil
	case ctap2.CredMgmtEnumerateCredsNext:
		if state == nil || len(state.creds) == 0 {
			return nil, ctap2.ErrNotAllowed
		}
		cred := state.creds[0]
		state.creds = state.creds[1:]
		s.credMgmt = state
		return credMgmtCredential(&cred), nil
	case ctap2.CredMgmtGetCredsMetadata, ctap2.CredMgmtEnumerateRPsBegin,
		ctap2.CredMgmtEnumerateCredsBegin, ctap2.CredMgmtDeleteCredential:
	default:
		return nil, ctap2.ErrInvalidSubcommand
	}

	if err := s.checkCredMgmtAuth(req); err != nil {
		return nil, err
	}
	var params ctap2.CredMgmtParams
	if req.SubCommandParams != nil {
		if err := ctap2.Unmarshal(req.SubCommandParams, &params); err != nil {
			return nil, err
		}
	}

	creds, err := s.loadPasskeys()
	if err != nil {
		return nil, err
	}

	switch req.SubCommand {
	case ctap2.CredMgmtGetCredsMetadata:
		existing := len(creds)
		remaining := passkeys.MaxCredentials - existing
		return ctap2.CredMgmtResp{
			ExistingResidentCredentialsCount:             &existing,
			MaxPossibleRemainingResidentCredentialsCount: &remaining,
		}, nil

	case ctap2.CredMgmtEnumerateRPsBegin:
		var rps []ctap2.RelyingParty
		index := make(map[string]int)
		for _, c := range creds {
			if i, ok := index[c.RPID]; ok {
				if c.RPName != "" {
					rps[i].Name = c.RPName
				}
				continue
			}
			index[c.RPID] = len(rps)
			rps = append(rps, ctap2.RelyingParty{ID: c.RPID, Name: c.RPName})
		}
		if len(rps) == 0 {
			return nil, ctap2.ErrNoCredentials
		}
		s.credMgmt = &credMgmtState{chanID: chanID, rps: rps[1:]}
		h := sha256.Sum256([]byte(rps[0].ID))
		return ctap2.CredMgmtResp{RP: &rps[0], RPIDHash: h[:], TotalRPs: len(rps)}, nil

	case ctap2.CredMgmtEnumerateCredsBegin:
		if params.RPIDHash == nil {
			return nil, ctap2.ErrMissingParameter
		}
		var matching []passkeys.Credential
		for _, c := range creds {
			h := sha256.Sum256([]byte(c.RPID))
			if bytes.Equal(h[:], params.RPIDHash) {
				matching = append(matching, c)
			}
		}
		if len(matching) == 0 {
			return nil, ctap2.ErrNoCredentials
		}
		s.credMgmt = &credMgmtState{chanID: chanID, creds: matching[1:]}
		resp := credMgmtCredential(&matching[0])
		resp.TotalCredentials = len(matching)
		return resp, nil

	case ctap2.CredMgmtDeleteCredential:
		if params.CredentialID == nil {
			return nil, ctap2.ErrMissingParameter
		}
		// kept reuses creds' backing array, so copy the deleted entry
		// instead of pointing into creds
		kept := creds[:0]
		var deleted *passkeys.Credential
		for _, c := range creds {
			if bytes.Equal(c.ID, params.CredentialID.ID) {
				d := c
				deleted = &d
				continue
			}
			kept = append(kept, c)
		}
		if deleted == nil {
			return nil, ctap2.ErrNoCredentials
		}
		log.Printf("deleting passkey rp=%s user=%s", logName(deleted.RPID), logName(deleted.UserName))
		if err := s.passkeys.Save(kept); err != nil {
			return nil, err
		}
		return nil, nil
	}
	panic("unreachable")
}

// checkCredMgmtAuth verifies the pinUvAuthParam of a credential management
// request: an authentication of the subcommand and its encoded parameters
// with the pinToken.
func (s *server) checkCredMgmtAuth(req *ctap2.CredMgmtReq) error {
	if req.PinUvAuthParam == nil {
		return ctap2.ErrPinRequired
	}
	proto := ctap2.LookupPINProtocol(req.PinUvAuthProtocol)
	if proto == nil {
		if req.PinUvAuthProtocol == 0 {
			return ctap2.ErrMissingParameter
		}
		return ctap2.ErrInvalidParameter
	}
	set, err := s.pins.PINSet()
	if err != nil {
		return err
	}
	if !set {
		return ctap2.ErrPinNotSet
	}
	if s.pin.sshOnly {
		return ctap2.ErrPinAuthInvalid
	}
	msg := append([]byte{byte(req.SubCommand)}, req.SubCommandParams...)
	if !ctap2.VerifyPINAuth(proto, s.pin.pinToken, msg, req.PinUvAuthParam) {
		return ctap2.ErrPinAuthInvalid
	}
	return nil
}

func credMgmtCredential(c *passkeys.Credential) ctap2.CredMgmtResp {
	return ctap2.CredMgmtResp{
		User: &ctap2.User{ID: c.UserID, Name: c.UserName, DisplayName: c.UserDisplayName},
		CredentialID: &ctap2.CredentialDescriptor{
			Type: ctap2.CredentialTypePublic,
			ID:   c.ID,
		},
		PublicKey: c.PublicKey,
	}
}
