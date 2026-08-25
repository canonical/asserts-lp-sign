// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package assertslpsign

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
	//lint:ignore SA1019 openpgp interop is required to talk to lp-signing; snapd itself uses this package
	"golang.org/x/crypto/openpgp/armor"
	//lint:ignore SA1019 openpgp interop is required to talk to lp-signing; snapd itself uses this package
	"golang.org/x/crypto/openpgp/packet"
	check "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
)

func Test(t *testing.T) { check.TestingT(t) }

type backendSuite struct{}

var _ = check.Suite(&backendSuite{})

type mockSigningService struct {
	servicePublicKey        *[32]byte
	servicePrivateKey       *[32]byte
	lastSignRequest         lpSigningSignRequest
	armoredSignature        []byte
	signingKey              *rsa.PrivateKey
	responsePublicKey       []byte
	responsePublicKeyBase64 string
	omitPublicKey           bool
	errorMessage            string
	nonceValue              [24]byte
}

func newMockSigningService(c *check.C, armoredSignature []byte, responsePublicKey []byte) *mockSigningService {
	servicePublicKey, servicePrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)
	service := &mockSigningService{
		servicePublicKey:  servicePublicKey,
		servicePrivateKey: servicePrivateKey,
		armoredSignature:  armoredSignature,
		responsePublicKey: responsePublicKey,
	}
	copy(service.nonceValue[:], []byte("0123456789abcdefghijklmn"))
	return service
}

func (s *mockSigningService) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-key":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"service-key": base64.StdEncoding.EncodeToString(s.servicePublicKey[:]),
			})
		case "/nonce":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"nonce": base64.StdEncoding.EncodeToString(s.nonceValue[:]),
			})
		case "/sign":
			s.handleSign(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *mockSigningService) handleSign(w http.ResponseWriter, r *http.Request) {
	clientPublicKey, requestNonce, responseNonce, ciphertext := decodeBoxedRequest(r)
	plaintext, ok := box.Open(nil, ciphertext, requestNonce, clientPublicKey, s.servicePrivateKey)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var request lpSigningSignRequest
	if err := json.Unmarshal(plaintext, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.lastSignRequest = request

	status := http.StatusOK
	var responseBody []byte
	if s.errorMessage != "" {
		status = http.StatusBadRequest
		responseBody, _ = json.Marshal(map[string]any{
			"error_list": []map[string]string{{"message": s.errorMessage}},
		})
	} else {
		armoredSignature := s.armoredSignature
		if s.signingKey != nil {
			message, err := base64.StdEncoding.DecodeString(request.Message)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			armoredSignature, _, err = makeArmoredDetachedSignatureBytes(s.signingKey, message)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		response := map[string]string{
			"signed-message": base64.StdEncoding.EncodeToString(armoredSignature),
		}
		if !s.omitPublicKey {
			publicKey := s.responsePublicKeyBase64
			if publicKey == "" {
				publicKey = base64.StdEncoding.EncodeToString(s.responsePublicKey)
			}
			response["public-key"] = publicKey
		}
		responseBody, _ = json.Marshal(response)
	}

	boxed := box.Seal(nil, responseBody, responseNonce, clientPublicKey, s.servicePrivateKey)
	w.Header().Set("Content-Type", "application/x-boxed-json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(boxed)))
}

func decodeBoxedRequest(r *http.Request) (*[32]byte, *[24]byte, *[24]byte, []byte) {
	clientPublicKey := new([32]byte)
	decodedClientPublicKey, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Client-Public-Key"))
	copy(clientPublicKey[:], decodedClientPublicKey)

	requestNonce := new([24]byte)
	decodedRequestNonce, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Nonce"))
	copy(requestNonce[:], decodedRequestNonce)

	responseNonce := new([24]byte)
	decodedResponseNonce, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Response-Nonce"))
	copy(responseNonce[:], decodedResponseNonce)

	body, _ := io.ReadAll(r.Body)
	decodedBody, _ := base64.StdEncoding.DecodeString(string(body))

	return clientPublicKey, requestNonce, responseNonce, decodedBody
}

func makeArmoredDetachedSignature(c *check.C, privateKey *rsa.PrivateKey, content []byte) ([]byte, []byte) {
	armored, raw, err := makeArmoredDetachedSignatureBytes(privateKey, content)
	c.Assert(err, check.IsNil)
	return armored, raw
}

func makeArmoredDetachedSignatureBytes(privateKey *rsa.PrivateKey, content []byte) ([]byte, []byte, error) {
	sig := new(packet.Signature)
	sig.PubKeyAlgo = packet.PubKeyAlgoRSA
	sig.Hash = crypto.SHA512
	sig.CreationTime = time.Now()

	h := crypto.SHA512.New()
	h.Write(content)
	err := sig.Sign(h, packet.NewRSAPrivateKey(time.Unix(1, 0), privateKey), &packet.Config{DefaultHash: crypto.SHA512})
	if err != nil {
		return nil, nil, err
	}

	raw := bytes.NewBuffer(nil)
	if err := sig.Serialize(raw); err != nil {
		return nil, nil, err
	}

	armored := bytes.NewBuffer(nil)
	armorWriter, err := armor.Encode(armored, "PGP SIGNATURE", nil)
	if err != nil {
		return nil, nil, err
	}
	if err := sig.Serialize(armorWriter); err != nil {
		return nil, nil, err
	}
	if err := armorWriter.Close(); err != nil {
		return nil, nil, err
	}

	return armored.Bytes(), raw.Bytes(), nil
}

func makeOpenPGPRSAPublicKeyBytes(publicKey *rsa.PublicKey) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := packet.NewRSAPublicKey(time.Unix(1, 0), publicKey).Serialize(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func makeArmoredOpenPGPRSAPublicKeyBytes(publicKey *rsa.PublicKey) ([]byte, error) {
	rawPublicKey, err := makeOpenPGPRSAPublicKeyBytes(publicKey)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(nil)
	armorWriter, err := armor.Encode(buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return nil, err
	}
	if _, err := armorWriter.Write(rawPublicKey); err != nil {
		return nil, err
	}
	if err := armorWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func makeArmoredOpenPGPECDSAPublicKeyBytes(publicKey *ecdsa.PublicKey) ([]byte, error) {
	rawPublicKey, err := makeOpenPGPECDSAPublicKeyBytes(publicKey)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(nil)
	armorWriter, err := armor.Encode(buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return nil, err
	}
	if _, err := armorWriter.Write(rawPublicKey); err != nil {
		return nil, err
	}
	if err := armorWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func makeOpenPGPECDSAPublicKeyBytes(publicKey *ecdsa.PublicKey) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := packet.NewECDSAPublicKey(time.Unix(1, 0), publicKey).Serialize(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func makeAccountKey(c *check.C, pubKey asserts.PublicKey) *asserts.AccountKey {
	store := assertstest.NewStoreStack("trusted", nil)
	brandAcct := assertstest.NewAccount(store, "brand", map[string]any{
		"account-id": "brand-id",
	}, "")
	return assertstest.NewAccountKey(store, brandAcct, nil, pubKey, "")
}

func generateX25519Keypair(random io.Reader) (*[32]byte, *[32]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	privateKey := new([32]byte)
	copy(privateKey[:], priv.Bytes())
	publicKey := new([32]byte)
	copy(publicKey[:], priv.PublicKey().Bytes())
	return publicKey, privateKey, nil
}

func (s *backendSuite) TestConstructorRejectsMissingAccountKey(c *check.C) {
	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	_, err = NewKeypairMgrBackend(Config{
		BaseURL:          "http://example.com",
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  nil,
			Fingerprint: "FINGERPRINT",
		}},
	})
	c.Assert(err, check.ErrorMatches, `cannot create lp-signing backend: missing account-key assertion`)
}

func (s *backendSuite) TestSignDearmorsDetachedSignature(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	armored, raw := makeArmoredDetachedSignature(c, rsaPrivKey, []byte("content to sign"))
	servicePublicKey, err := makeArmoredOpenPGPRSAPublicKeyBytes(&rsaPrivKey.PublicKey)
	c.Assert(err, check.IsNil)
	service := newMockSigningService(c, armored, servicePublicKey)
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR1",
		}},
	})
	c.Assert(err, check.IsNil)

	loaded, err := backend.LoadByID(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	c.Check(loaded.Name, check.Equals, "LPFPR1")
	c.Check(loaded.KeyHandle, check.Equals, "LPFPR1")
	signed, err := backend.Sign(loaded.KeyHandle, []byte("content to sign"))
	c.Assert(err, check.IsNil)

	c.Check(signed, check.DeepEquals, raw)
	c.Check(service.lastSignRequest.KeyType, check.Equals, lpSigningKeyTypeOpenPGP)
	c.Check(service.lastSignRequest.Fingerprint, check.Equals, "LPFPR1")
	c.Check(service.lastSignRequest.MessageName, check.Equals, lpSigningMessageName)
	c.Check(service.lastSignRequest.Mode, check.Equals, lpSigningModeDetached)
	decodedMessage, err := base64.StdEncoding.DecodeString(service.lastSignRequest.Message)
	c.Assert(err, check.IsNil)
	c.Check(decodedMessage, check.DeepEquals, []byte("content to sign"))
	_, err = packet.Read(bytes.NewReader(signed))
	c.Assert(err, check.IsNil)
}

func (s *backendSuite) TestExternalKeypairManagerIntegration(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	servicePublicKey, err := makeArmoredOpenPGPRSAPublicKeyBytes(&rsaPrivKey.PublicKey)
	c.Assert(err, check.IsNil)
	service := newMockSigningService(c, nil, servicePublicKey)
	service.signingKey = rsaPrivKey
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR2",
		}},
	})
	c.Assert(err, check.IsNil)

	kmgr, err := asserts.NewExternalKeypairManagerWithBackend(backend, asserts.ExtKeypairMgrConfig{
		SigningWith: "lp-signing",
		KeyStore:    "lp-signing",
	})
	c.Assert(err, check.IsNil)

	pk, err := kmgr.Get(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	c.Check(pk.PublicKey().ID(), check.Equals, accountKey.PublicKeyID())
	loaded, err := backend.LoadByID(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	c.Check(loaded.Name, check.Equals, "LPFPR2")
	c.Check(loaded.KeyHandle, check.Equals, "LPFPR2")

	store := assertstest.NewStoreStack("trusted", nil)
	brandAcct := assertstest.NewAccount(store, "brand", map[string]any{
		"account-id": "brand-id",
	}, "")
	brandAccKey := assertstest.NewAccountKey(store, brandAcct, nil, pk.PublicKey(), "")

	signDB, err := asserts.OpenDatabase(&asserts.DatabaseConfig{KeypairManager: kmgr})
	c.Assert(err, check.IsNil)
	checkDB, err := asserts.OpenDatabase(&asserts.DatabaseConfig{
		Backstore: asserts.NewMemoryBackstore(),
		Trusted:   store.Trusted,
	})
	c.Assert(err, check.IsNil)
	err = checkDB.Add(store.StoreAccountKey(""))
	c.Assert(err, check.IsNil)
	err = checkDB.Add(brandAcct)
	c.Assert(err, check.IsNil)
	err = checkDB.Add(brandAccKey)
	c.Assert(err, check.IsNil)

	modelHeaders := map[string]any{
		"authority-id": "brand-id",
		"brand-id":     "brand-id",
		"model":        "model",
		"series":       "16",
		"architecture": "amd64",
		"base":         "core18",
		"gadget":       "gadget",
		"kernel":       "pc-kernel",
		"timestamp":    time.Now().Format(time.RFC3339),
	}
	a, err := signDB.Sign(asserts.ModelType, modelHeaders, nil, pk.PublicKey().ID())
	c.Assert(err, check.IsNil)
	err = checkDB.Check(a)
	c.Assert(err, check.IsNil)

	_, err = kmgr.GetByName("default")
	c.Assert(err, check.ErrorMatches, `cannot get key by name from sign-only external keypair manager`)
	_, err = kmgr.Export("default")
	c.Assert(err, check.ErrorMatches, `cannot get key by name from sign-only external keypair manager`)
	_, err = kmgr.List()
	c.Assert(err, check.ErrorMatches, `cannot list keys in sign-only external keypair manager`)
	c.Check(service.lastSignRequest.Fingerprint, check.Equals, "LPFPR2")
	c.Check(service.lastSignRequest.MessageName, check.Equals, lpSigningMessageName)
}

func (s *backendSuite) TestSignAcceptsArmoredResponsePublicKey(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	armoredSignature, rawSignature := makeArmoredDetachedSignature(c, rsaPrivKey, []byte("content to sign"))
	servicePublicKey, err := makeArmoredOpenPGPRSAPublicKeyBytes(&rsaPrivKey.PublicKey)
	c.Assert(err, check.IsNil)
	service := newMockSigningService(c, armoredSignature, servicePublicKey)
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR2A",
		}},
	})
	c.Assert(err, check.IsNil)

	loaded, err := backend.LoadByID(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	signed, err := backend.Sign(loaded.KeyHandle, []byte("content to sign"))
	c.Assert(err, check.IsNil)
	c.Check(signed, check.DeepEquals, rawSignature)
}

func (s *backendSuite) TestSignRejectsMissingResponsePublicKey(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	armored, _ := makeArmoredDetachedSignature(c, rsaPrivKey, []byte("content to sign"))
	service := newMockSigningService(c, armored, nil)
	service.omitPublicKey = true
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR3",
		}},
	})
	c.Assert(err, check.IsNil)

	loaded, err := backend.LoadByID(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	_, err = backend.Sign(loaded.KeyHandle, []byte("content to sign"))
	c.Assert(err, check.ErrorMatches, `cannot decode lp-signing sign response: missing public-key`)
}

func (s *backendSuite) TestSignRejectsInvalidResponsePublicKeyBase64(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	armored, _ := makeArmoredDetachedSignature(c, rsaPrivKey, []byte("content to sign"))
	service := newMockSigningService(c, armored, nil)
	service.responsePublicKeyBase64 = "%"
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR4",
		}},
	})
	c.Assert(err, check.IsNil)

	loaded, err := backend.LoadByID(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	_, err = backend.Sign(loaded.KeyHandle, []byte("content to sign"))
	c.Assert(err, check.ErrorMatches, `cannot decode lp-signing sign response public key: illegal base64 data at input byte 0`)
}

func (s *backendSuite) TestSignRejectsInvalidOpenPGPResponsePublicKey(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	armored, _ := makeArmoredDetachedSignature(c, rsaPrivKey, []byte("content to sign"))
	service := newMockSigningService(c, armored, []byte("not an openpgp public key"))
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR5",
		}},
	})
	c.Assert(err, check.IsNil)

	loaded, err := backend.LoadByID(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	_, err = backend.Sign(loaded.KeyHandle, []byte("content to sign"))
	c.Assert(err, check.ErrorMatches, `cannot decode lp-signing sign response public key: .*`)
}

func (s *backendSuite) TestSignRejectsNonRSAResponsePublicKey(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	armored, _ := makeArmoredDetachedSignature(c, rsaPrivKey, []byte("content to sign"))
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, check.IsNil)
	servicePublicKey, err := makeArmoredOpenPGPECDSAPublicKeyBytes(&ecdsaPrivateKey.PublicKey)
	c.Assert(err, check.IsNil)
	service := newMockSigningService(c, armored, servicePublicKey)
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR6",
		}},
	})
	c.Assert(err, check.IsNil)

	loaded, err := backend.LoadByID(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	_, err = backend.Sign(loaded.KeyHandle, []byte("content to sign"))
	c.Assert(err, check.ErrorMatches, `cannot decode lp-signing sign response public key: unsupported OpenPGP public key type \*ecdsa.PublicKey`)
}

func (s *backendSuite) TestSignRejectsMismatchedResponsePublicKeyID(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	armored, _ := makeArmoredDetachedSignature(c, rsaPrivKey, []byte("content to sign"))
	mismatchedPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, check.IsNil)
	servicePublicKey, err := makeArmoredOpenPGPRSAPublicKeyBytes(&mismatchedPrivateKey.PublicKey)
	c.Assert(err, check.IsNil)
	service := newMockSigningService(c, armored, servicePublicKey)
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR7",
		}},
	})
	c.Assert(err, check.IsNil)

	loaded, err := backend.LoadByID(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	_, err = backend.Sign(loaded.KeyHandle, []byte("content to sign"))
	c.Assert(err, check.ErrorMatches, `cannot sign with lp-signing: service used unexpected key with id ".*", expected ".*"`)
}

func (s *backendSuite) TestLoadByCanonicalFingerprint(c *check.C) {
	privKey, _ := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          "http://example.com",
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR0",
		}},
	})
	c.Assert(err, check.IsNil)

	loaded, err := backend.LoadByCanonicalFingerprint("LPFPR0")
	c.Assert(err, check.IsNil)
	c.Check(loaded.Name, check.Equals, "LPFPR0")
	c.Check(loaded.KeyHandle, check.Equals, "LPFPR0")
	c.Check(loaded.PublicKey.ID(), check.Equals, accountKey.PublicKeyID())
}

func (s *backendSuite) TestLoadByCanonicalFingerprintMissingKey(c *check.C) {
	privKey, _ := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          "http://example.com",
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR0",
		}},
	})
	c.Assert(err, check.IsNil)

	_, err = backend.LoadByCanonicalFingerprint("MISSING")
	c.Assert(err, check.ErrorMatches, `missing key`)
}
