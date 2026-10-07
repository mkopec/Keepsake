package gnome

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// gcr's secret exchange ("sx-aes-1", gcr/gcr-secret-exchange.c) protects
// passwords between the prompter and the client: Diffie-Hellman in the 1536
// bit MODP group (RFC 3526 group 5), the shared secret padded to the size
// of the prime, HKDF-SHA256 without salt and info to a 16 byte key, and
// AES-128-CBC with PKCS#7 padding. The prompter refuses prompts without a
// valid exchange, even confirmations.
var (
	modp1536, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
	modpGenerator = big.NewInt(2)
)

const exchangeKeySize = 16

var errBadExchange = errors.New("invalid secret exchange from the prompter")

type secretExchange struct {
	priv, pub *big.Int
}

func newSecretExchange() (*secretExchange, error) {
	priv, err := rand.Int(rand.Reader, new(big.Int).Sub(modp1536, big.NewInt(2)))
	if err != nil {
		return nil, err
	}
	priv.Add(priv, big.NewInt(1))
	return &secretExchange{priv: priv, pub: new(big.Int).Exp(modpGenerator, priv, modp1536)}, nil
}

// begin returns the client's first message.
func (e *secretExchange) begin() string {
	return "[sx-aes-1]\npublic=" + base64.StdEncoding.EncodeToString(e.pub.Bytes()) + "\n"
}

// receive decrypts the secret in the prompter's message.
func (e *secretExchange) receive(msg string) (string, error) {
	fields := parseExchange(msg)
	if fields == nil {
		return "", errBadExchange
	}
	peerBytes, err1 := base64.StdEncoding.DecodeString(fields["public"])
	iv, err2 := base64.StdEncoding.DecodeString(fields["iv"])
	ct, err3 := base64.StdEncoding.DecodeString(fields["secret"])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != aes.BlockSize ||
		len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return "", errBadExchange
	}
	peer := new(big.Int).SetBytes(peerBytes)
	if peer.Cmp(big.NewInt(1)) <= 0 || peer.Cmp(new(big.Int).Sub(modp1536, big.NewInt(1))) >= 0 {
		return "", errBadExchange
	}

	z := new(big.Int).Exp(peer, e.priv, modp1536).FillBytes(make([]byte, (modp1536.BitLen()+7)/8))
	key := make([]byte, exchangeKeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, z, nil, nil), key); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	return unpad(plain)
}

func unpad(b []byte) (string, error) {
	n := int(b[len(b)-1])
	if n == 0 || n > aes.BlockSize || n > len(b) {
		return "", errBadExchange
	}
	pad := b[len(b)-n:]
	for _, c := range pad {
		if subtle.ConstantTimeByteEq(c, byte(n)) != 1 {
			return "", errBadExchange
		}
	}
	return string(b[:len(b)-n]), nil
}

// parseExchange parses the key file format of an exchange message.
func parseExchange(msg string) map[string]string {
	fields := map[string]string{}
	section := false
	sc := bufio.NewScanner(strings.NewReader(msg))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case line == "[sx-aes-1]":
			section = true
		case strings.HasPrefix(line, "["):
			section = false
		case section:
			if k, v, ok := strings.Cut(line, "="); ok {
				fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	if fields["public"] == "" {
		return nil
	}
	return fields
}
