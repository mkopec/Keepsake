package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psanford/tpm-fido/ctap2"
	"github.com/psanford/tpm-fido/fidohid"
	"github.com/psanford/tpm-fido/passkeys"
	"github.com/psanford/tpm-fido/ui"
)

// aaguid identifies the tpm-fido authenticator model:
// 5a578a82-5a81-402a-a89a-bb6e12f90eff
var aaguid = []byte{0x5a, 0x57, 0x8a, 0x82, 0x5a, 0x81, 0x40, 0x2a, 0xa8, 0x9a, 0xbb, 0x6e, 0x12, 0xf9, 0x0e, 0xff}

const (
	userPresenceTimeout = 30 * time.Second
	keepaliveInterval   = 100 * time.Millisecond
	maxMsgSize          = 1200
)

func (s *server) handleCBOR(token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	ka := startKeepalive(token, evt)
	resp, err := s.dispatchCBOR(evt, ka)
	ka.stop()

	status := ctap2.StatusOK
	var body []byte
	if err == nil && resp != nil {
		body, err = ctap2.Marshal(resp)
	}
	if err != nil {
		if !errors.As(err, &status) {
			log.Printf("ctap2 cmd 0x%02x err: %s", evt.CBOR[0], err)
			status = ctap2.ErrOther
		}
		body = nil
	}

	if err := token.WriteCBOR(evt, byte(status), body); err != nil {
		log.Printf("write ctap2 response err: %s", err)
	}
}

func (s *server) dispatchCBOR(evt fidohid.AuthEvent, ka *keepalive) (interface{}, error) {
	cmd, params := evt.CBOR[0], evt.CBOR[1:]

	// GetNextAssertion must directly follow GetAssertion
	if cmd != ctap2.CmdGetNextAssertion {
		s.nextAssertion = nil
	}
	// credential management enumerations must not be interrupted either
	if cmd != ctap2.CmdCredentialMgmt && cmd != ctap2.CmdCredentialMgmtPreview {
		s.credMgmt = nil
	}

	// Refuse everything but GetInfo while the session is locked: nobody
	// can confirm a request, and requests without user presence (silent
	// probing, hmac-secret with up=false) shouldn't succeed while the user
	// is away either.
	if cmd != ctap2.CmdGetInfo && s.sessionLocked(evt.Ctx) {
		return nil, ctap2.ErrOperationDenied
	}

	switch cmd {
	case ctap2.CmdGetInfo:
		log.Print("got ctap2 GetInfo")
		pinSet, err := s.pins.PINSet()
		if err != nil {
			return nil, err
		}
		return ctap2.GetInfoResp{
			// FIDO_2_1_PRE advertises the credential management
			// preview command.
			Versions:   []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE"},
			Extensions: []string{ctap2.ExtHMACSecret},
			AAGUID:     aaguid,
			Options: map[string]bool{
				"rk":        true,
				"up":        true,
				"plat":      false,
				"clientPin": pinSet,

				"credentialMgmtPreview": true,
			},
			MaxMsgSize:   maxMsgSize,
			PinProtocols: []uint{2, 1},
		}, nil
	case ctap2.CmdClientPIN:
		var req ctap2.ClientPINReq
		if err := ctap2.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		return s.clientPIN(&req)
	case ctap2.CmdMakeCredential:
		var req ctap2.MakeCredentialReq
		if err := ctap2.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		return s.makeCredential(evt, ka, &req)
	case ctap2.CmdGetAssertion:
		var req ctap2.GetAssertionReq
		if err := ctap2.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		return s.getAssertion(evt, ka, &req)
	case ctap2.CmdCredentialMgmt, ctap2.CmdCredentialMgmtPreview:
		var req ctap2.CredMgmtReq
		if err := ctap2.Unmarshal(params, &req); err != nil {
			return nil, err
		}
		return s.credentialManagement(&req)
	case ctap2.CmdReset:
		return s.reset(evt, ka)
	case ctap2.CmdGetNextAssertion:
		log.Print("got ctap2 GetNextAssertion")
		return s.getNextAssertion()
	default:
		log.Printf("unsupported ctap2 command 0x%02x", cmd)
		return nil, ctap2.ErrInvalidCommand
	}
}

func (s *server) makeCredential(evt fidohid.AuthEvent, ka *keepalive, req *ctap2.MakeCredentialReq) (interface{}, error) {
	if req.ClientDataHash == nil || req.RP == nil || req.RP.ID == "" || req.User == nil || req.User.ID == nil || req.PubKeyCredParams == nil {
		return nil, ctap2.ErrMissingParameter
	}

	log.Printf("got ctap2 MakeCredential rp=%s", req.RP.ID)

	if err := s.selectAuthenticator(evt, ka, req.PinUvAuthParam); err != nil {
		return nil, err
	}

	es256 := false
	for _, p := range req.PubKeyCredParams {
		if p.Type == ctap2.CredentialTypePublic && p.Alg == ctap2.AlgES256 {
			es256 = true
			break
		}
	}
	if !es256 {
		return nil, ctap2.ErrUnsupportedAlgorithm
	}

	rk := req.Options["rk"]
	if up, ok := req.Options["up"]; ok && !up {
		return nil, ctap2.ErrInvalidOption
	}
	if err := s.checkUVOption(req.Options, req.PinUvAuthParam); err != nil {
		return nil, err
	}

	hmacSecret, err := hmacSecretCreate(req.Extensions)
	if err != nil {
		return nil, err
	}

	// CTAP 2.0 requires the PIN for every registration once it is set.
	uv, err := s.checkPINUVAuth(req.PinUvAuthParam, req.PinUvAuthProtocol, req.ClientDataHash, true)
	if err != nil {
		return nil, err
	}

	rpIDHash := sha256.Sum256([]byte(req.RP.ID))

	for _, cred := range req.ExcludeList {
		if cred.Type == ctap2.CredentialTypePublic && s.ownsCredential(cred.ID, rpIDHash[:]) {
			// Require user presence so a site can't silently probe for
			// registered credentials.
			if err := s.confirmPresence(evt, ka, alreadyRegisteredPrompt(displayText(req.RP.ID, 253))); err != nil {
				return nil, err
			}
			return nil, ctap2.ErrCredentialExcluded
		}
	}

	prompt := registerPrompt(displayText(req.RP.ID, 253), userLabel(req.User))
	if rk {
		prompt = passkeyPrompt(displayText(req.RP.ID, 253), userLabel(req.User))
	}
	if err := s.confirmPresence(evt, ka, prompt); err != nil {
		return nil, err
	}

	credID, x, y, err := s.signer.RegisterKey(rpIDHash[:], hmacSecret, rk)
	if err != nil {
		return nil, fmt.Errorf("register key err: %w", err)
	}
	coseKey, err := ctap2.COSEKeyES256(x, y)
	if err != nil {
		return nil, err
	}
	counter, err := s.signer.Counter()
	if err != nil {
		return nil, fmt.Errorf("counter err: %w", err)
	}

	flags := byte(ctap2.FlagUserPresent)
	if uv {
		flags |= ctap2.FlagUserVerified
	}
	var extensions []byte
	if hmacSecret {
		if extensions, err = ctap2.Marshal(map[string]bool{ctap2.ExtHMACSecret: true}); err != nil {
			return nil, err
		}
	}

	attested := ctap2.AttestedCredentialData(aaguid, credID, coseKey)
	authData := ctap2.AuthenticatorData(rpIDHash[:], flags, counter, attested, extensions)

	sig, err := s.signer.SignASN1(credID, rpIDHash[:], signedDigest(authData, req.ClientDataHash))
	if err != nil {
		return nil, fmt.Errorf("attestation sign err: %w", err)
	}

	if rk {
		err := s.storePasskey(passkeys.Credential{
			ID:              credID,
			RPID:            req.RP.ID,
			RPName:          req.RP.Name,
			UserID:          req.User.ID,
			UserName:        req.User.Name,
			UserDisplayName: req.User.DisplayName,
			PublicKey:       coseKey,
			Created:         time.Now().Unix(),
		})
		if err != nil {
			return nil, fmt.Errorf("store passkey err: %w", err)
		}
	}

	return ctap2.MakeCredentialResp{
		Fmt:      "packed",
		AuthData: authData,
		AttStmt: ctap2.PackedAttStmt{
			Alg: ctap2.AlgES256,
			Sig: sig,
		},
	}, nil
}

func (s *server) getAssertion(evt fidohid.AuthEvent, ka *keepalive, req *ctap2.GetAssertionReq) (interface{}, error) {
	if req.RPID == "" || req.ClientDataHash == nil {
		return nil, ctap2.ErrMissingParameter
	}

	log.Printf("got ctap2 GetAssertion rp=%s allowList=%d", req.RPID, len(req.AllowList))

	if err := s.selectAuthenticator(evt, ka, req.PinUvAuthParam); err != nil {
		return nil, err
	}
	if _, ok := req.Options["rk"]; ok {
		return nil, ctap2.ErrUnsupportedOption
	}
	if err := s.checkUVOption(req.Options, req.PinUvAuthParam); err != nil {
		return nil, err
	}
	up := true
	if v, ok := req.Options["up"]; ok {
		up = v
	}

	uv, err := s.checkPINUVAuth(req.PinUvAuthParam, req.PinUvAuthProtocol, req.ClientDataHash, false)
	if err != nil {
		return nil, err
	}

	hmacReq, err := s.parseHMACSecretGet(req.Extensions)
	if err != nil {
		return nil, err
	}

	rpIDHash := sha256.Sum256([]byte(req.RPID))

	var (
		credID []byte
		// discoverable credentials, when allowList is empty
		discovered []passkeys.Credential
	)
	if len(req.AllowList) > 0 {
		for _, cred := range req.AllowList {
			if cred.Type == ctap2.CredentialTypePublic && s.ownsCredential(cred.ID, rpIDHash[:]) {
				credID = cred.ID
				break
			}
		}
	} else {
		if discovered, err = s.discoverablePasskeys(req.RPID); err != nil {
			return nil, err
		}
		if len(discovered) > 0 {
			credID = discovered[0].ID
		}
	}
	if credID == nil {
		return nil, ctap2.ErrNoCredentials
	}

	var flags byte
	if up {
		if err := s.confirmPresence(evt, ka, signInPrompt(displayText(req.RPID, 253))); err != nil {
			return nil, err
		}
		flags |= ctap2.FlagUserPresent
	}
	if uv {
		flags |= ctap2.FlagUserVerified
	}

	resp, err := s.assert(credID, rpIDHash[:], req.ClientDataHash, flags, uv, hmacReq)
	if err != nil {
		return nil, err
	}

	if discovered != nil {
		resp.User = passkeyUser(&discovered[0], uv)
		if len(discovered) > 1 {
			// The platform lets the user pick and fetches the other
			// assertions with GetNextAssertion.
			resp.NumberOfCredentials = len(discovered)
			s.nextAssertion = &assertionState{
				creds:          discovered[1:],
				rpIDHash:       rpIDHash[:],
				clientDataHash: req.ClientDataHash,
				flags:          flags,
				uv:             uv,
				hmacReq:        hmacReq,
				expires:        time.Now().Add(nextAssertionTimeout),
			}
		}
	}
	return resp, nil
}

// assert signs an assertion with credID.
func (s *server) assert(credID, rpIDHash, clientDataHash []byte, flags byte, uv bool, hmacReq *hmacSecretRequest) (*ctap2.GetAssertionResp, error) {
	var extensions []byte
	if hmacReq != nil {
		var err error
		if extensions, err = s.hmacSecretOutput(hmacReq, credID, rpIDHash, uv); err != nil {
			return nil, err
		}
	}

	counter, err := s.signer.Counter()
	if err != nil {
		return nil, fmt.Errorf("counter err: %w", err)
	}
	authData := ctap2.AuthenticatorData(rpIDHash, flags, counter, nil, extensions)

	sig, err := s.signer.SignASN1(credID, rpIDHash, signedDigest(authData, clientDataHash))
	if err != nil {
		return nil, fmt.Errorf("assertion sign err: %w", err)
	}

	return &ctap2.GetAssertionResp{
		Credential: ctap2.CredentialDescriptor{
			Type: ctap2.CredentialTypePublic,
			ID:   credID,
		},
		AuthData:  authData,
		Signature: sig,
	}, nil
}

// checkUVOption handles the "uv" option. There is no built-in user
// verification, but when a PIN is set the platform can verify the user with
// it, so the request is answered with PIN_REQUIRED (as libfido2 expects) and
// the platform retries with a pinUvAuthParam.
func (s *server) checkUVOption(options map[string]bool, pinUvAuthParam *[]byte) error {
	if !options["uv"] || pinUvAuthParam != nil {
		return nil
	}
	set, err := s.pins.PINSet()
	if err != nil {
		return err
	}
	if set {
		return ctap2.ErrPinRequired
	}
	return ctap2.ErrUnsupportedOption
}

// selectAuthenticator handles a zero length pinUvAuthParam, which platforms
// send to let the user pick an authenticator by touching it. It returns nil
// for any other pinUvAuthParam.
func (s *server) selectAuthenticator(evt fidohid.AuthEvent, ka *keepalive, param *[]byte) error {
	if param == nil || len(*param) > 0 {
		return nil
	}
	if err := s.confirmPresence(evt, ka, selectPrompt()); err != nil {
		return err
	}
	set, err := s.pins.PINSet()
	if err != nil {
		return err
	}
	if set {
		return ctap2.ErrPinInvalid
	}
	return ctap2.ErrPinNotSet
}

// ownsCredential reports whether credID is a credential created by this
// authenticator for rpIDHash. Discoverable credentials must also be in the
// passkey store: deleting a passkey revokes it.
func (s *server) ownsCredential(credID, rpIDHash []byte) bool {
	if s.signer.IsDiscoverable(credID) {
		stored, err := s.storedPasskey(credID, rpIDHash)
		if err != nil {
			log.Printf("passkey store err: %s", err)
			return false
		}
		if stored == nil {
			return false
		}
	}

	dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))
	_, err := s.signer.SignASN1(credID, rpIDHash, dummySig[:])
	return err == nil
}

// confirmPresence asks the user to confirm the request. It returns nil if the
// user confirmed and the CTAP2 status to return otherwise.
func (s *server) confirmPresence(evt fidohid.AuthEvent, ka *keepalive, prompt ui.Prompt) error {
	ka.set(fidohid.KeepaliveUPNeeded)
	defer ka.set(fidohid.KeepaliveProcessing)

	ctx, cancel := context.WithTimeout(evt.Ctx, userPresenceTimeout)
	defer cancel()

	// close the dialog if the session gets locked while it is shown
	var locked atomic.Bool
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if s.sessionLocked(ctx) {
					locked.Store(true)
					cancel()
					return
				}
			}
		}
	}()

	ok, err := s.pe.Confirm(ctx, prompt)
	switch {
	case evt.Ctx.Err() != nil:
		return ctap2.ErrKeepaliveCancel
	case locked.Load():
		return ctap2.ErrOperationDenied
	case ctx.Err() != nil:
		return ctap2.ErrUserActionTimeout
	case err != nil:
		log.Printf("confirmation dialog err: %s", err)
		return ctap2.ErrOperationDenied
	case !ok:
		return ctap2.ErrOperationDenied
	}
	return nil
}

func signedDigest(authData, clientDataHash []byte) []byte {
	h := sha256.New()
	h.Write(authData)
	h.Write(clientDataHash)
	return h.Sum(nil)
}

func userLabel(u *ctap2.User) string {
	label := u.Name
	if label == "" {
		label = u.DisplayName
	}
	return displayText(label, 64)
}

// keepalive periodically sends CTAPHID_KEEPALIVE messages while a CTAP2
// request is being processed.
type keepalive struct {
	status atomic.Uint32
	done   chan struct{}
	wg     sync.WaitGroup
}

func startKeepalive(token *fidohid.SoftToken, evt fidohid.AuthEvent) *keepalive {
	ka := &keepalive{done: make(chan struct{})}
	ka.set(fidohid.KeepaliveProcessing)
	ka.wg.Add(1)
	go func() {
		defer ka.wg.Done()
		ticker := time.NewTicker(keepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := token.KeepAlive(evt, byte(ka.status.Load())); err != nil {
					log.Printf("write keepalive err: %s", err)
				}
			case <-ka.done:
				return
			}
		}
	}()
	return ka
}

func (ka *keepalive) set(status byte) {
	ka.status.Store(uint32(status))
}

// stop stops sending keepalives. No keepalive is sent after stop returns.
func (ka *keepalive) stop() {
	close(ka.done)
	ka.wg.Wait()
}
