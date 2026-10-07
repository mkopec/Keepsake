package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/mkopec/keepsake/src/ctap2"
	"github.com/mkopec/keepsake/src/passkeys"
)

// nextAssertionTimeout is how long GetNextAssertion can be called after
// GetAssertion.
const nextAssertionTimeout = 30 * time.Second

// newPasskeyStore returns the passkey store at path. Its key is fetched from
// the signer once and cached until the authenticator is reset.
func (s *server) newPasskeyStore(path string) *passkeys.Store {
	return &passkeys.Store{
		Path: path,
		Key: func() ([]byte, error) {
			if s.storeKey == nil {
				key, err := s.signer.StoreKey()
				if err != nil {
					return nil, err
				}
				s.storeKey = key
			}
			return s.storeKey, nil
		},
		Version: s.signer.StoreVersion,
		Advance: s.signer.AdvanceStoreVersion,
	}
}

// migratePasskeyStore re-saves an unversioned (v1) passkey store as a
// versioned one, once, when the store counter was just created.
func (s *server) migratePasskeyStore() error {
	s.passkeys.AllowUnversioned = true
	creds, err := s.loadPasskeys()
	s.passkeys.AllowUnversioned = false
	if err != nil || creds == nil {
		return err
	}
	log.Printf("protecting the passkey store against rollback")
	return s.passkeys.Save(creds)
}

// loadPasskeys loads the passkey store. A store that can't be decrypted
// (after the TPM was cleared, or the device key replaced outside Keepsake)
// is moved aside, since its passkeys can't be used anymore.
func (s *server) loadPasskeys() ([]passkeys.Credential, error) {
	creds, err := s.passkeys.Load()
	if errors.Is(err, passkeys.ErrUndecryptable) || errors.Is(err, passkeys.ErrRolledBack) {
		name, merr := s.passkeys.MoveAside(time.Now().Format("20060102-150405"))
		if merr != nil {
			return nil, fmt.Errorf("%w; moving it aside failed: %s", err, merr)
		}
		if errors.Is(err, passkeys.ErrRolledBack) {
			log.Printf("WARNING: the passkey store is older than the last one Keepsake saved (restored from a backup?); "+
				"it could bring back deleted passkeys, so it was moved to %s and isn't used", name)
		} else {
			log.Printf("passkey store can't be decrypted with this TPM, moved it to %s", name)
		}
		return nil, nil
	}
	return creds, err
}

// storePasskey adds cred to the store, replacing a passkey for the same
// relying party and user.
func (s *server) storePasskey(cred passkeys.Credential) error {
	creds, err := s.loadPasskeys()
	if err != nil {
		return err
	}
	kept := creds[:0]
	for _, c := range creds {
		if c.RPID == cred.RPID && bytes.Equal(c.UserID, cred.UserID) {
			log.Printf("replacing passkey for rp=%s user=%s", logName(c.RPID), logName(c.UserName))
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) >= passkeys.MaxCredentials {
		return ctap2.ErrKeyStoreFull
	}
	return s.passkeys.Save(append(kept, cred))
}

// storedPasskey returns the stored passkey with the given ID and relying
// party, or nil.
func (s *server) storedPasskey(credID, rpIDHash []byte) (*passkeys.Credential, error) {
	creds, err := s.loadPasskeys()
	if err != nil {
		return nil, err
	}
	for i, c := range creds {
		h := sha256.Sum256([]byte(c.RPID))
		if bytes.Equal(c.ID, credID) && bytes.Equal(h[:], rpIDHash) {
			return &creds[i], nil
		}
	}
	return nil, nil
}

// discoverablePasskeys returns the usable passkeys for rpID, newest first.
// Without user verification, passkeys with credProtect level 2 or 3 aren't
// discoverable.
func (s *server) discoverablePasskeys(rpID string, uv bool) ([]passkeys.Credential, error) {
	creds, err := s.loadPasskeys()
	if err != nil {
		return nil, err
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	var out []passkeys.Credential
	// New passkeys are appended to the store, so walking it backwards puts
	// passkeys created in the same second newest first too.
	for i := len(creds) - 1; i >= 0; i-- {
		c := creds[i]
		if c.RPID != rpID {
			continue
		}
		if info, err := s.signer.KeyInfo(c.ID); err != nil || (!uv && info.CredProtect >= 2) {
			continue
		}
		if s.ownsCredential(c.ID, rpIDHash[:], uv) {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created > out[j].Created })
	return out, nil
}

// passkeyUser returns the user entity returned with an assertion. CTAP 2.0
// only allows user names to be returned after user verification.
func passkeyUser(c *passkeys.Credential, uv bool) *ctap2.User {
	u := &ctap2.User{ID: c.UserID}
	if uv {
		u.Name = c.UserName
		u.DisplayName = c.UserDisplayName
	}
	return u
}

// assertionState holds the remaining credentials of a GetAssertion request
// for GetNextAssertion.
type assertionState struct {
	// the CTAPHID channel of the GetAssertion request; other channels
	// (other programs) can't continue it
	chanID         uint32
	creds          []passkeys.Credential
	rpIDHash       []byte
	clientDataHash []byte
	flags          byte
	uv             bool
	hmacReq        *hmacSecretRequest
	expires        time.Time
}

func (s *server) getNextAssertion(chanID uint32) (interface{}, error) {
	st := s.nextAssertion
	if st == nil || st.chanID != chanID {
		return nil, ctap2.ErrNotAllowed
	}
	if len(st.creds) == 0 || time.Now().After(st.expires) {
		s.nextAssertion = nil
		return nil, ctap2.ErrNotAllowed
	}
	cred := st.creds[0]
	st.creds = st.creds[1:]

	resp, err := s.assert(cred.ID, st.rpIDHash, st.clientDataHash, st.flags, st.uv, st.hmacReq)
	if err != nil {
		return nil, err
	}
	resp.User = passkeyUser(&cred, st.uv)
	return resp, nil
}
