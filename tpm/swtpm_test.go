package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// recorder records everything sent to and received from the TPM, as a bus
// sniffer would.
type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

type recordingConn struct {
	io.ReadWriteCloser
	r *recorder
}

func (c recordingConn) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	c.r.mu.Lock()
	c.r.buf.Write(p[:n])
	c.r.mu.Unlock()
	return n, err
}

func (c recordingConn) Write(p []byte) (int, error) {
	c.r.mu.Lock()
	c.r.buf.Write(p)
	c.r.mu.Unlock()
	return c.ReadWriteCloser.Write(p)
}

func (r *recorder) contains(secret []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Contains(r.buf.Bytes(), secret)
}

// testSlot is far from the UIDs of real users, so tests can run against the
// swtpm used for manual testing.
const testSlot = 60000

// swtpm returns a TPM on the swtpm socket in $TPMFIDO_SWTPM with all traffic
// recorded, after removing what an earlier run left behind.
func swtpm(t *testing.T) (*TPM, *recorder, Handles) {
	return swtpmUser(t, testSlot, filepath.Join(t.TempDir(), "user-secret"))
}

func swtpmUser(t *testing.T, slot int, secretFile string) (*TPM, *recorder, Handles) {
	sock := os.Getenv("TPMFIDO_SWTPM")
	if sock == "" {
		t.Skip("set TPMFIDO_SWTPM to an swtpm socket")
	}
	h := HandlesForSlot(slot)
	cleanup := func() {
		rwc, err := tpmutil.OpenTPM(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer rwc.Close()
		tpm := transport.FromReadWriter(rwc)
		for _, idx := range []uint32{h.CounterIndex, h.PINIndex, h.StateIndex} {
			if pub, err := (tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(idx)}).Execute(tpm); err == nil {
				tpm2.NVUndefineSpace{AuthHandle: ownerAuth, NVIndex: tpm2.NamedHandle{Handle: tpm2.TPMHandle(idx), Name: pub.NVName}}.Execute(tpm)
			}
		}
		if pub, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(h.DeviceKey)}).Execute(tpm); err == nil {
			tpm2.EvictControl{Auth: ownerAuth, ObjectHandle: tpm2.NamedHandle{Handle: tpm2.TPMHandle(h.DeviceKey), Name: pub.Name},
				PersistentHandle: tpm2.TPMIDHPersistent(h.DeviceKey)}.Execute(tpm)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	rec := &recorder{}
	h.SRKNameFile = filepath.Join(t.TempDir(), "srk-name")
	h.UserSecretFile = secretFile
	tp, err := newTPM(sock, h, func() (io.ReadWriteCloser, error) {
		rwc, err := tpmutil.OpenTPM(sock)
		return recordingConn{rwc, rec}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	return tp, rec, h
}

func pinHashOf(pin string) []byte {
	h := sha256.Sum256([]byte(pin))
	return h[:16]
}

func TestSecretsNotOnBus(t *testing.T) {
	tp, rec, _ := swtpm(t)
	pin1, pin2 := pinHashOf("1234"), pinHashOf("5678")

	if err := tp.SetPIN(pin1, nil, 8); err != nil {
		t.Fatal(err)
	}
	if ok, err := tp.VerifyPIN(pin1); !ok || err != nil {
		t.Fatalf("verify PIN: %v %v", ok, err)
	}
	if ok, err := tp.VerifyPIN(pinHashOf("0000")); ok || err != nil {
		t.Fatalf("verify wrong PIN: %v %v", ok, err)
	}

	rp := sha256.Sum256([]byte("example.com"))
	kh, _, _, err := tp.RegisterKey(rp[:], KeyOptions{HMACSecret: true})
	if err != nil {
		t.Fatal(err)
	}
	uvSecret, err := tp.HMACSecret(kh, rp[:], pin1)
	if err != nil {
		t.Fatal(err)
	}
	noUVSecret, err := tp.HMACSecret(kh, rp[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	storeKey, err := tp.StoreKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := tp.SetPIN(pin2, pin1, 8); err != nil {
		t.Fatal(err)
	}
	if again, err := tp.HMACSecret(kh, rp[:], pin2); err != nil || !bytes.Equal(again, uvSecret) {
		t.Fatalf("UV secret after PIN change: %v", err)
	}

	for name, secret := range map[string][]byte{
		"PIN hash": pin1, "new PIN hash": pin2,
		"PIN auth": tp.pinAuth(pin1), "new PIN auth": tp.pinAuth(pin2),
		"device key auth": tp.deviceKeyAuth(), "user secret": tp.userSecret,
		"hmac-secret (UV)": uvSecret, "hmac-secret (no UV)": noUVSecret, "store key": storeKey,
	} {
		if rec.contains(secret) {
			t.Errorf("%s visible on the bus", name)
		}
	}

	// the recorder does see unencrypted secrets
	err = tp.withTPM(func(tpm transport.TPM) error {
		clear, err := tp.deviceHMAC(tpm, []byte("sanity"), false)
		if err == nil && !rec.contains(clear) {
			t.Error("recorder missed an unencrypted HMAC")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPINBoundCredential(t *testing.T) {
	tp, _, _ := swtpm(t)
	rp := sha256.Sum256([]byte("example.com"))

	if _, _, _, err := tp.RegisterKey(rp[:], KeyOptions{CredProtect: 3}); !errors.Is(err, ErrNoPIN) {
		t.Fatalf("bound credential without PIN: %v", err)
	}

	pin := pinHashOf("1234")
	if err := tp.SetPIN(pin, nil, 8); err != nil {
		t.Fatal(err)
	}
	kh, x, y, err := tp.RegisterKey(rp[:], KeyOptions{CredProtect: 3, Discoverable: true})
	if err != nil {
		t.Fatal(err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	digest := sha256.Sum256([]byte("message"))

	if _, err := tp.SignASN1(kh, rp[:], digest[:], nil); !errors.Is(err, ErrPINRequired) {
		t.Fatalf("sign without PIN: %v", err)
	}
	if _, err := tp.SignASN1(kh, rp[:], digest[:], pinHashOf("0000")); err == nil {
		t.Fatal("signed with the wrong PIN")
	}
	sig, err := tp.SignASN1(kh, rp[:], digest[:], pin)
	if err != nil || !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatalf("sign with PIN: %v", err)
	}

	// someone using the TPM directly can't sign with an empty password
	err = tp.withTPM(func(tpm transport.TPM) error {
		key, _, done, err := tp.loadCredential(tpm, kh, rp[:])
		if err != nil {
			return err
		}
		defer done()
		_, err = tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{Handle: key.ObjectHandle, Name: key.Name, Auth: tpm2.PasswordAuth(nil)},
			Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
			InScheme: tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256})},
			Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
		}.Execute(tpm)
		if err == nil {
			t.Error("bound key signed with an empty password")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// survives a PIN change, with the new PIN only
	pin2 := pinHashOf("5678")
	if err := tp.SetPIN(pin2, pin, 8); err != nil {
		t.Fatal(err)
	}
	if _, err := tp.SignASN1(kh, rp[:], digest[:], pin); err == nil {
		t.Fatal("signed with the old PIN")
	}
	if sig, err := tp.SignASN1(kh, rp[:], digest[:], pin2); err != nil || !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatalf("sign with new PIN: %v", err)
	}

	// a new PIN index (PIN removed and set again, e.g. by someone with
	// owner authorization) doesn't satisfy the policy
	err = tp.withTPM(func(tpm transport.TPM) error {
		name, _, _, err := tp.pinIndex(tpm)
		if err != nil {
			return err
		}
		_, err = tpm2.NVUndefineSpace{AuthHandle: ownerAuth, NVIndex: tp.pinIndexHandleNamed(name)}.Execute(tpm)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.SetPIN(pin2, nil, 8); err != nil {
		t.Fatal(err)
	}
	if _, err := tp.SignASN1(kh, rp[:], digest[:], pin2); err == nil {
		t.Fatal("bound key usable with a re-created PIN")
	}
}

func TestKeyHandleFlagsAuthenticated(t *testing.T) {
	tp, _, _ := swtpm(t)
	rp := sha256.Sum256([]byte("example.com"))
	kh, _, _, err := tp.RegisterKey(rp[:], KeyOptions{Discoverable: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.CheckKey(kh, rp[:]); err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("other.com"))
	if err := tp.CheckKey(kh, other[:]); err == nil {
		t.Fatal("key handle valid for another relying party")
	}

	// clear the discoverable flag (the byte before the last 20 seed bytes)
	tampered := append([]byte(nil), kh...)
	v := &tampered[len(tampered)-seedSizeBytes-1]
	if *v != keyHandleFormat|keyHandleFlagDiscoverable {
		t.Fatalf("unexpected version byte %x", *v)
	}
	*v = keyHandleFormat
	if info, _ := tp.KeyInfo(tampered); info.Discoverable {
		t.Fatal("flag not cleared")
	}
	if err := tp.CheckKey(tampered, rp[:]); err == nil {
		t.Fatal("key handle with modified flags accepted")
	}
}

func TestSRKPinned(t *testing.T) {
	_, _, h := swtpm(t)
	if err := os.WriteFile(h.SRKNameFile, []byte("not the SRK"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(os.Getenv("TPMFIDO_SWTPM"), h); !errors.Is(err, ErrSRKMismatch) {
		t.Fatalf("SRK mismatch: %v", err)
	}
}

func TestLockoutStatus(t *testing.T) {
	tp, _, _ := swtpm(t)
	st, err := tp.LockoutStatus()
	if err != nil || st.MaxAuthFail == 0 {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestUsersIsolated(t *testing.T) {
	alice, _, aliceHandles := swtpmUser(t, testSlot, filepath.Join(t.TempDir(), "alice"))
	bob, _, _ := swtpmUser(t, testSlot+1, filepath.Join(t.TempDir(), "bob"))

	rp := sha256.Sum256([]byte("example.com"))
	digest := sha256.Sum256([]byte("message"))
	pin := pinHashOf("1234")
	if err := alice.SetPIN(pin, nil, 8); err != nil {
		t.Fatal(err)
	}
	cred, _, _, err := alice.RegisterKey(rp[:], KeyOptions{HMACSecret: true})
	if err != nil {
		t.Fatal(err)
	}
	bound, _, _, err := alice.RegisterKey(rp[:], KeyOptions{CredProtect: 3})
	if err != nil {
		t.Fatal(err)
	}

	// Bob, in his own slot, has his own PIN and can't use Alice's credentials
	if set, _ := bob.PINSet(); set {
		t.Fatal("Bob sees Alice's PIN")
	}
	if err := bob.CheckKey(cred, rp[:]); err == nil {
		t.Fatal("Bob accepts Alice's credential")
	}

	// tpm-fido refuses to start with Alice's slot and another secret
	h := aliceHandles
	h.UserSecretFile = filepath.Join(t.TempDir(), "mallory")
	if _, err := New(os.Getenv("TPMFIDO_SWTPM"), h); err == nil {
		t.Fatal("started with another user's device key")
	}

	// Mallory using Alice's handles directly, without her user secret
	mallory := &TPM{
		devicePath:      alice.devicePath,
		counterIndex:    alice.counterIndex,
		pinIndexHandle:  alice.pinIndexHandle,
		stateIndex:      alice.stateIndex,
		deviceKeyHandle: alice.deviceKeyHandle,
		deviceKeyName:   alice.deviceKeyName,
		srkName:         alice.srkName,
		userSecret:      bytes.Repeat([]byte{1}, UserSecretSize),
	}
	if err := mallory.CheckKey(cred, rp[:]); err == nil {
		t.Error("Mallory can load Alice's credential")
	}
	if _, err := mallory.SignASN1(cred, rp[:], digest[:], nil); err == nil {
		t.Error("Mallory can sign with Alice's credential")
	}
	if _, err := mallory.SignASN1(bound, rp[:], digest[:], pin); err == nil {
		t.Error("Mallory can sign with Alice's PIN-bound credential, even knowing the PIN")
	}
	if _, err := mallory.HMACSecret(cred, rp[:], nil); err == nil {
		t.Error("Mallory can compute Alice's hmac-secret")
	}
	if _, err := mallory.StoreKey(); err == nil {
		t.Error("Mallory can compute Alice's passkey store key")
	}
	if ok, _ := mallory.VerifyPIN(pin); ok {
		t.Error("Mallory can check Alice's PIN")
	}

	// Alice is unaffected
	if _, err := alice.SignASN1(cred, rp[:], digest[:], nil); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.SignASN1(bound, rp[:], digest[:], pin); err != nil {
		t.Fatal(err)
	}
}

// go-tpm can't use HMAC session authorization values containing zero
// bytes; derived ones must work for any user secret. (Before they were hex
// encoded, about 12% of user secrets failed.)
func TestDerivedAuthAnySecret(t *testing.T) {
	tp, _, _ := swtpm(t)
	rp := sha256.Sum256([]byte("example.com"))
	d := sha256.Sum256([]byte("m"))
	for i := 0; i < 48; i++ {
		tp.userSecret = mustRand(UserSecretSize)
		pin := pinHashOf(fmt.Sprint(i))
		err := tp.withTPM(func(tpm transport.TPM) error {
			tpm2.EvictControl{Auth: ownerAuth, ObjectHandle: tpm2.NamedHandle{Handle: tpm2.TPMHandle(tp.deviceKeyHandle), Name: tp.deviceKeyName},
				PersistentHandle: tpm2.TPMIDHPersistent(tp.deviceKeyHandle)}.Execute(tpm)
			return tp.createDeviceKey(tpm)
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := tp.SetPIN(pin, nil, 8); err != nil {
			t.Fatal(err)
		}
		kh, _, _, err := tp.RegisterKey(rp[:], KeyOptions{CredProtect: 3, HMACSecret: true})
		if err != nil {
			t.Fatalf("secret %x: %v", tp.userSecret, err)
		}
		if ok, err := tp.VerifyPIN(pin); !ok || err != nil {
			t.Fatalf("secret %x: verify PIN: %v %v", tp.userSecret, ok, err)
		}
		if _, err := tp.SignASN1(kh, rp[:], d[:], pin); err != nil {
			t.Fatalf("secret %x: %v", tp.userSecret, err)
		}
		if _, err := tp.HMACSecret(kh, rp[:], nil); err != nil {
			t.Fatalf("secret %x: %v", tp.userSecret, err)
		}
	}
}

func TestDeriveNoZeroBytes(t *testing.T) {
	tp := &TPM{}
	for i := 0; i < 1000; i++ {
		tp.userSecret = mustRand(UserSecretSize)
		for _, v := range [][]byte{tp.deviceKeyAuth(), tp.pinAuth(mustRand(16))} {
			if len(v) != 32 || bytes.IndexByte(v, 0) >= 0 {
				t.Fatalf("bad auth value %x", v)
			}
		}
	}
}

func hmacSHA256(key []byte, data ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// Someone who recorded the bus sees the primary key template of a
// credential. With it they can load the credential key, but format 0x30
// keys can't be used without their authorization value, which only crosses
// the bus encrypted.
func TestSniffedTemplateCantSign(t *testing.T) {
	tp, rec, _ := swtpm(t)
	rp := sha256.Sum256([]byte("example.com"))
	kh, _, _, err := tp.RegisterKey(rp[:], KeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("message"))
	if _, err := tp.SignASN1(kh, rp[:], digest[:], nil); err != nil {
		t.Fatal(err)
	}

	private, public, seedField, _ := decodeKeyHandle(kh)
	seed, flags, _ := parseSeed(seedField)
	var pSeed, auth []byte
	err = tp.withTPM(func(tpm transport.TPM) error {
		var err error
		if pSeed, err = tp.primarySeed(tpm, seed, flags); err != nil {
			return err
		}
		auth, err = tp.credAuth(tpm, seed, flags)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rec.contains(pSeed) {
		t.Fatal("expected the primary seed on the bus (this test assumes a sniffer sees it)")
	}
	if rec.contains(auth) {
		t.Fatal("credential authorization value visible on the bus")
	}

	// the attacker: sniffed template, no authorization value
	err = tp.withTPM(func(tpm transport.TPM) error {
		p, err := createPrimary(tpm, primaryTemplate(pSeed, rp[:], true))
		if err != nil {
			return err
		}
		defer flush(tpm, p.ObjectHandle)
		k, err := tpm2.Load{ParentHandle: parentAuth(p), InPrivate: tpm2.TPM2BPrivate{Buffer: private},
			InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](public)}.Execute(tpm)
		if err != nil {
			return err
		}
		defer flush(tpm, k.ObjectHandle)
		_, err = tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{Handle: k.ObjectHandle, Name: k.Name, Auth: tpm2.PasswordAuth(nil)},
			Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
			InScheme: tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256})},
			Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
		}.Execute(tpm)
		if err == nil {
			t.Error("signed with the sniffed template and an empty password")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBootStateBinding(t *testing.T) {
	sock := os.Getenv("TPMFIDO_SWTPM")
	tp, _, h := swtpm(t)
	// recreate the device key bound to PCR 7
	tp.bindBootState = true
	if err := tp.Reset(); err != nil {
		t.Fatal(err)
	}
	if bound, changed := tp.DeviceKeyBound(); !bound || changed {
		t.Fatalf("bound=%v changed=%v", bound, changed)
	}
	rp := sha256.Sum256([]byte("example.com"))
	kh, _, _, err := tp.RegisterKey(rp[:], KeyOptions{HMACSecret: true})
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("m"))
	if _, err := tp.SignASN1(kh, rp[:], d[:], nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tp.HMACSecret(kh, rp[:], nil); err != nil {
		t.Fatal(err)
	}

	// change the boot state: extend PCR 7
	err = tp.withTPM(func(tpm transport.TPM) error {
		_, err := tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(7), Auth: tpm2.PasswordAuth(nil)},
			Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
				HashAlg: tpm2.TPMAlgSHA256, Digest: bytes.Repeat([]byte{1}, 32)}}},
		}.Execute(tpm)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tp.SignASN1(kh, rp[:], d[:], nil); !errors.Is(err, ErrBootStateChanged) {
		t.Fatalf("sign after boot state change: %v", err)
	}

	// tpm-fido still starts, so the user can reset
	restarted, err := newTPM(sock, h, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed := restarted.DeviceKeyBound(); !changed {
		t.Fatal("boot state change not detected at startup")
	}
	if err := restarted.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, changed := restarted.DeviceKeyBound(); changed {
		t.Fatal("still changed after reset")
	}
}

// Credentials created before format 0x30 keep working.
func TestFormatV2StillWorks(t *testing.T) {
	tp, _, _ := swtpm(t)
	rp := sha256.Sum256([]byte("example.com"))
	pin := pinHashOf("1234")
	if err := tp.SetPIN(pin, nil, 8); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("m"))
	for _, o := range []KeyOptions{{CredProtect: 1, HMACSecret: true}, {CredProtect: 3, Discoverable: true}} {
		kh, x, y, err := tp.registerKey(rp[:], keyHandleFlags{KeyOptions: o, format: keyHandleFormatV2})
		if err != nil {
			t.Fatal(err)
		}
		if f, _ := keyHandleInfo(kh); f.format != keyHandleFormatV2 || f.credAuth {
			t.Fatalf("flags %+v", f)
		}
		sig, err := tp.SignASN1(kh, rp[:], d[:], pin)
		if err != nil || !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, d[:], sig) {
			t.Fatalf("%+v: %v", o, err)
		}
	}
}
