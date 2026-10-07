package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
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

// testHandles don't overlap with the default ones, so the test can run
// against the swtpm used for manual testing.
var testHandles = Handles{
	CounterIndex: 0x0100F1E0,
	PINIndex:     0x0100F1E1,
	StateIndex:   0x0100F1E2,
	DeviceKey:    0x8100F1E0,
}

// swtpm returns a TPM on the swtpm socket in $TPMFIDO_SWTPM with all traffic
// recorded, after removing what an earlier run left behind.
func swtpm(t *testing.T) (*TPM, *recorder, Handles) {
	sock := os.Getenv("TPMFIDO_SWTPM")
	if sock == "" {
		t.Skip("set TPMFIDO_SWTPM to an swtpm socket")
	}
	cleanup := func() {
		rwc, err := tpmutil.OpenTPM(sock)
		if err != nil {
			t.Fatal(err)
		}
		defer rwc.Close()
		tpm := transport.FromReadWriter(rwc)
		for _, idx := range []uint32{testHandles.CounterIndex, testHandles.PINIndex, testHandles.StateIndex} {
			if pub, err := (tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(idx)}).Execute(tpm); err == nil {
				tpm2.NVUndefineSpace{AuthHandle: ownerAuth, NVIndex: tpm2.NamedHandle{Handle: tpm2.TPMHandle(idx), Name: pub.NVName}}.Execute(tpm)
			}
		}
		if pub, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(testHandles.DeviceKey)}).Execute(tpm); err == nil {
			tpm2.EvictControl{Auth: ownerAuth, ObjectHandle: tpm2.NamedHandle{Handle: tpm2.TPMHandle(testHandles.DeviceKey), Name: pub.Name},
				PersistentHandle: tpm2.TPMIDHPersistent(testHandles.DeviceKey)}.Execute(tpm)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	rec := &recorder{}
	h := testHandles
	h.SRKNameFile = filepath.Join(t.TempDir(), "srk-name")
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
