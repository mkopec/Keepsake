package tpm

import (
	"crypto/sha256"
	"io"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"golang.org/x/crypto/hkdf"
)

// legacyPrimaryTemplate is the primary key template as earlier versions
// built it with the legacy go-tpm API.
func legacyPrimaryTemplate(seed, applicationParam []byte, noDA bool) legacy.Public {
	info := append([]byte("tpm-fido-application-key"), applicationParam...)
	r := hkdf.New(sha256.New, seed, []byte{}, info)
	unique := legacy.ECPoint{XRaw: make([]byte, 32), YRaw: make([]byte, 32)}
	io.ReadFull(r, unique.XRaw)
	io.ReadFull(r, unique.YRaw)

	attrs := legacy.FlagRestricted | legacy.FlagDecrypt |
		legacy.FlagFixedTPM | legacy.FlagFixedParent |
		legacy.FlagSensitiveDataOrigin | legacy.FlagUserWithAuth
	if noDA {
		attrs |= legacy.FlagNoDA
	}
	return legacy.Public{
		Type:       legacy.AlgECC,
		NameAlg:    legacy.AlgSHA256,
		Attributes: attrs,
		ECCParameters: &legacy.ECCParams{
			Symmetric: &legacy.SymScheme{Alg: legacy.AlgAES, KeyBits: 128, Mode: legacy.AlgCFB},
			CurveID:   legacy.CurveNISTP256,
			Point:     unique,
		},
	}
}
