package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"io/fs"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/psanford/tpm-fido/src/attestation"
	"github.com/psanford/tpm-fido/src/ctap2"
	"github.com/psanford/tpm-fido/src/fidoauth"
	"github.com/psanford/tpm-fido/src/fidohid"
	"github.com/psanford/tpm-fido/src/memory"
	"github.com/psanford/tpm-fido/src/passkeys"
	"github.com/psanford/tpm-fido/src/sitesignatures"
	"github.com/psanford/tpm-fido/src/statuscode"
	"github.com/psanford/tpm-fido/src/tpm"
	"github.com/psanford/tpm-fido/src/ui"
)

var backend = flag.String("backend", "tpm", "tpm|memory")
var device = flag.String("device", "/dev/tpmrm0", "TPM device path")
var slot = flag.Int("slot", -1, "TPM handle slot (0-65535), default: the user ID. Each user of the TPM needs their own")
var bindBootState = flag.Bool("bind-boot-state", false, "bind credentials created after the next reset to the boot state (PCR 7, the Secure Boot configuration); see docs/security.md")
var allowSilent = flag.Bool("allow-silent", false, "allow hmac-secret outputs and U2F signatures without user presence (e.g. LUKS enrolled with --fido2-with-user-presence=no)")
var verbose = flag.Bool("verbose", false, "log relying party IDs and user names")
var passkeyStore = flag.String("passkey-store", "", "passkey store path (default $XDG_DATA_HOME/tpm-fido/passkeys)")

func main() {
	flag.Parse()
	if os.Getenv("JOURNAL_STREAM") != "" {
		// journald adds its own timestamps
		log.SetFlags(0)
	}
	s := newServer()
	s.run()
}

type server struct {
	pe     *ui.Prompter
	locker Locker
	signer Signer
	pins   PINStore
	pin    *pinState

	passkeys      *passkeys.Store
	storeKey      []byte
	nextAssertion *assertionState
	credMgmt      *credMgmtState

	dialogs dialogLimiter

	// see askpassservice.go
	grant       presenceGrant
	lastRequest atomic.Int64

	// lockKnown is set once the screen lock state could be read
	lockKnown atomic.Bool
}

type Signer interface {
	RegisterKey(applicationParam []byte, opts tpm.KeyOptions) ([]byte, *big.Int, *big.Int, error)
	// KeyInfo returns the properties a key handle was created with,
	// without checking that it is valid.
	KeyInfo(keyHandle []byte) (tpm.KeyOptions, error)
	// CheckKey returns nil if keyHandle is a valid credential for
	// applicationParam.
	CheckKey(keyHandle, applicationParam []byte) error
	// SignASN1 signs with a credential. Credentials with credProtect
	// level 3 need uvPinHash, the hash of the verified PIN.
	SignASN1(keyHandle, applicationParam, digest, uvPinHash []byte) ([]byte, error)
	Counter() (uint32, error)
	// HMACSecret returns the hmac-secret CredRandom of a credential, the
	// one used with user verification if uvPinHash is set.
	HMACSecret(keyHandle, rpIDHash, uvPinHash []byte) ([]byte, error)
	// StoreKey returns the passkey store encryption key.
	StoreKey() ([]byte, error)
	// StoreVersion and AdvanceStoreVersion are the passkey store's
	// anti-rollback counter, see passkeys.Store.
	StoreVersion() (uint64, error)
	AdvanceStoreVersion(v uint64) error
	// Reset invalidates every credential and removes the PIN.
	Reset() error
}

func newServer() *server {
	s := server{
		pin: newPINState(),
	}

	path := *passkeyStore
	if path == "" && *backend == "memory" {
		// the memory backend's keys don't outlive the process
		dir, err := os.MkdirTemp("", "tpm-fido-memory-")
		if err != nil {
			log.Fatal(err)
		}
		path = filepath.Join(dir, "passkeys")
	} else if path == "" {
		var err error
		if path, err = passkeys.DefaultPath(); err != nil {
			log.Fatal(err)
		}
	}

	if *backend == "tpm" {
		if *slot < 0 {
			*slot = os.Getuid()
		}
		if *slot > tpm.MaxSlot {
			log.Fatalf("user ID %d is too large for a TPM handle slot, choose one with -slot (0-%d) that no other user uses", *slot, tpm.MaxSlot)
		}
		handles := tpm.HandlesForSlot(*slot)
		handles.SRKNameFile = filepath.Join(filepath.Dir(path), "srk-name")
		handles.UserSecretFile = filepath.Join(filepath.Dir(path), "user-secret")
		handles.BindBootState = *bindBootState
		signer, err := tpm.New(*device, handles)
		if errors.Is(err, fs.ErrPermission) {
			log.Fatalf("%s: add your user to the group owning %s (usually tss) and log in again", err, *device)
		}
		if err != nil {
			log.Fatalf("TPM: %s", err)
		}
		warnLockout(signer)
		switch bound, changed := signer.DeviceKeyBound(); {
		case changed:
			log.Printf("WARNING: %s. Until then, no credential can be used.", tpm.ErrBootStateChanged)
		case *bindBootState && !bound:
			log.Printf("note: -bind-boot-state only applies to a new device key: reset the security key to bind the credentials to the boot state")
		case bound:
			log.Printf("credentials are bound to the boot state (PCR 7)")
		}
		if old := signer.LeftoverSharedObjects(); len(old) > 0 {
			log.Printf("note: TPM objects from an earlier tpm-fido development version are left at %#x; "+
				"their credentials don't work anymore. If no other user still runs that version, remove them "+
				"with tpm2_nvundefine -C o <index> and tpm2_evictcontrol -C o -c <handle>", old)
		}
		s.signer = signer
		s.pins = signer
	} else if *backend == "memory" {
		signer, err := memory.New()
		if err != nil {
			log.Fatal(err)
		}
		s.signer = signer
		s.pins = signer
	}
	s.passkeys = s.newPasskeyStore(path)
	if t, ok := s.signer.(*tpm.TPM); ok && t.StoreCounterNew() {
		if err := s.migratePasskeyStore(); err != nil {
			log.Fatalf("passkey store: %s", err)
		}
	}

	if err := s.setupDesktop(); err != nil {
		log.Fatal(err)
	}
	return &s
}

// warnLockout warns if the TPM's dictionary attack protection can't
// protect the PIN.
func warnLockout(t *tpm.TPM) {
	st, err := t.LockoutStatus()
	if err != nil {
		log.Printf("can't read the TPM's dictionary attack settings: %s", err)
		return
	}
	if !st.LockoutAuthSet {
		log.Printf("WARNING: the TPM's lockout authorization is not set. Anyone who can use the TPM " +
			"(e.g. members of the tss group) can reset its dictionary attack counter and guess the PIN " +
			"without limit, and can clear the TPM, destroying all its keys. Set it with " +
			"`tpm2_changeauth -c lockout <password>` and keep the password safe.")
	}
	if st.MaxAuthFail == 0 || st.MaxAuthFail > 32 {
		log.Printf("WARNING: the TPM allows %d wrong PINs before locking out", st.MaxAuthFail)
	}
}

func (s *server) run() {
	ctx := context.Background()

	token, err := fidohid.New(ctx, "tpm-fido")
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			log.Fatalf("create fido hid error: %s: your user needs read and write access to /dev/uhid, see docs/installing.md", err)
		}
		log.Fatalf("create fido hid error: %s", err)
	}

	go token.Run(ctx)

	// requests and PIN token expiry run on this goroutine, so they don't
	// race
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case evt := <-token.Events():
			s.handleEvent(ctx, token, evt)
			token.Release(evt)
		case <-ticker.C:
			s.pin.expire()
		}
	}
}

func (s *server) handleEvent(ctx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	if evt.Error != nil {
		log.Printf("got token error: %s", evt.Error)
		if evt.IsCBOR() {
			token.WriteCBOR(evt, byte(ctap2.ErrInvalidLength), nil)
		}
		return
	}

	if evt.IsCBOR() {
		s.handleCBOR(token, evt)
		return
	}

	req := evt.Req

	// While the session is locked, answer like a key waiting for a touch;
	// the host keeps retrying. Check-only requests don't sign anything.
	needsUser := req.Command == fidoauth.CmdRegister ||
		(req.Command == fidoauth.CmdAuthenticate && req.Authenticate.Ctrl != fidoauth.CtrlCheckOnly)
	if needsUser && s.sessionLocked(ctx) {
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		return
	}

	if req.Command == fidoauth.CmdAuthenticate {
		log.Printf("got AuthenticateCmd site=%s", logName(sitesignatures.FromAppParam(req.Authenticate.ApplicationParam)))

		s.noteRequest()
		s.handleAuthenticate(ctx, token, evt)
	} else if req.Command == fidoauth.CmdRegister {
		log.Printf("got RegisterCmd site=%s", logName(sitesignatures.FromAppParam(req.Register.ApplicationParam)))
		s.noteRequest()
		s.handleRegister(ctx, token, evt)
	} else if req.Command == fidoauth.CmdVersion {
		log.Print("got VersionCmd")
		s.handleVersion(ctx, token, evt)
	} else {
		log.Printf("unsupported request type: 0x%02x\n", req.Command)
		// send a not supported error for any commands that we don't understand.
		// Browsers depend on this to detect what features the token supports
		// (i.e. the u2f backwards compatibility)
		token.WriteResponse(ctx, evt, nil, statuscode.ClaNotSupported)
	}
}

func (s *server) handleVersion(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	token.WriteResponse(parentCtx, evt, []byte("U2F_V2"), statuscode.NoError)
}

func (s *server) handleAuthenticate(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req

	keyHandle := req.Authenticate.KeyHandle
	appParam := req.Authenticate.ApplicationParam[:]

	if !s.ownsCredential(keyHandle, appParam, false) {
		log.Printf("invalid key handle (size: %d)", len(keyHandle))

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}

		return
	}

	switch req.Authenticate.Ctrl {
	case fidoauth.CtrlCheckOnly,
		fidoauth.CtrlDontEnforeUserPresenceAndSign,
		fidoauth.CtrlEnforeUserPresenceAndSign:
	default:
		log.Printf("unknown authenticate control value: %d", req.Authenticate.Ctrl)

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send wrong-data msg err: %s", err)
		}
		return
	}

	// U2F signatures without user presence: browsers never ask for them,
	// and anyone who can open the device could otherwise sign silently.
	if req.Authenticate.Ctrl == fidoauth.CtrlDontEnforeUserPresenceAndSign && !*allowSilent {
		log.Print("U2F signature without user presence refused (see -allow-silent)")
		token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		return
	}

	if req.Authenticate.Ctrl == fidoauth.CtrlCheckOnly {
		// check if the provided key is known by the token
		log.Printf("check-only success")
		// test-of-user-presence-required: note that despite the name this signals a success condition
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}
		return
	}

	var userPresent uint8

	if req.Authenticate.Ctrl == fidoauth.CtrlEnforeUserPresenceAndSign {

		pinResultCh, err := s.pe.ConfirmPresence(signInPrompt(sitesignatures.Known(req.Authenticate.ApplicationParam)), req.Authenticate.ChallengeParam, req.Authenticate.ApplicationParam)

		if err != nil {
			log.Printf("pinentry err: %s", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)

			return
		}

		childCtx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
		defer cancel()

		select {
		case result := <-pinResultCh:
			if result.OK {
				userPresent = 0x01
			} else {
				if result.Error != nil {
					log.Printf("Got pinentry result err: %s", result.Error)
				}

				// Got user cancelation, we want to propagate that so the browser gives up.
				// This isn't normally supported by a key so there's no status code for this.
				// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
				err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
				if err != nil {
					log.Printf("Write WrongData resp err: %s", err)
				}
				return
			}
		case <-childCtx.Done():
			err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
			if err != nil {
				log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			}
			return
		}
	}

	signCounter, err := s.signer.Counter()
	if err != nil {
		log.Printf("counter err: %s", err)
		return
	}

	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sig, err := s.signer.SignASN1(keyHandle, appParam, sigHash.Sum(nil), nil)
	if err != nil {
		log.Fatalf("auth sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)

	err = token.WriteResponse(parentCtx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write auth response err: %s", err)
		return
	}
}

func (s *server) handleRegister(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	// U2F can't ask for the PIN. Once a PIN is set, registrations need it
	// (as over CTAP2), so U2F registrations are refused: browsers use
	// CTAP2 anyway.
	if set, err := s.pins.PINSet(); err != nil || set {
		log.Print("U2F registration refused: a PIN is set")
		token.WriteResponse(parentCtx, evt, nil, statuscode.InsNotSupported)
		return
	}
	ctx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
	defer cancel()
	req := evt.Req

	pinResultCh, err := s.pe.ConfirmPresence(registerPrompt(sitesignatures.Known(req.Register.ApplicationParam), ""), req.Register.ChallengeParam, req.Register.ApplicationParam)

	if err != nil {
		log.Printf("pinentry err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)

		return
	}

	select {
	case result := <-pinResultCh:
		if !result.OK {
			if result.Error != nil {
				log.Printf("Got pinentry result err: %s", result.Error)
			}

			// Got user cancelation, we want to propagate that so the browser gives up.
			// This isn't normally supported by a key so there's no status code for this.
			// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
			err := token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
			if err != nil {
				log.Printf("Write WrongData resp err: %s", err)
				return
			}
			return
		}

		s.registerSite(parentCtx, token, evt)
	case <-ctx.Done():
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func (s *server) registerSite(ctx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req

	keyHandle, x, y, err := s.signer.RegisterKey(req.Register.ApplicationParam[:], tpm.KeyOptions{})
	if err != nil {
		log.Printf("RegisteKey err: %s", err)
		return
	}

	if len(keyHandle) > 255 {
		log.Printf("Error: keyHandle too large: %d, max=255", len(keyHandle))
		return
	}

	childPubKey := elliptic.Marshal(elliptic.P256(), x, y)

	var toSign bytes.Buffer
	toSign.WriteByte(0)
	toSign.Write(req.Register.ApplicationParam[:])
	toSign.Write(req.Register.ChallengeParam[:])
	toSign.Write(keyHandle)
	toSign.Write(childPubKey)

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sum := sigHash.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sum)
	if err != nil {
		log.Fatalf("attestation sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(0x05) // reserved value
	out.Write(childPubKey)
	out.WriteByte(byte(len(keyHandle)))
	out.Write(keyHandle)
	out.Write(attestation.CertDer)
	out.Write(sig)

	err = token.WriteResponse(ctx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write register response err: %s", err)
		return
	}
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
