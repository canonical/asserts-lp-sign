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

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
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

const runMainEnv = "LPSIGNKEYMGR_TEST_RUN_MAIN"

// init lets the test binary act as lpsignkeymgr when exec'd by snapd's external keypair manager.
func init() {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}
}

func Test(t *testing.T) { check.TestingT(t) }

type mockLPSigning struct {
	servicePublicKey  *[32]byte
	servicePrivateKey *[32]byte
	signingKeys       map[string]*rsa.PrivateKey
	errorMessage      string

	mu           sync.Mutex
	signRequests []mockSignRequest
}

type mockSignRequest struct {
	KeyType     string `json:"key-type"`
	Fingerprint string `json:"fingerprint"`
	MessageName string `json:"message-name"`
	Message     string `json:"message"`
	Mode        string `json:"mode"`
}

func newMockLPSigning(c *check.C, signingKeys map[string]*rsa.PrivateKey) *mockLPSigning {
	servicePublicKey, servicePrivateKey, err := box.GenerateKey(rand.Reader)
	c.Assert(err, check.IsNil)
	return &mockLPSigning{
		servicePublicKey:  servicePublicKey,
		servicePrivateKey: servicePrivateKey,
		signingKeys:       signingKeys,
	}
}

func (s *mockLPSigning) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/service-key":
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service-key": base64.StdEncoding.EncodeToString(s.servicePublicKey[:]),
		})
	case "/nonce":
		var nonce [24]byte
		_, _ = rand.Read(nonce[:])
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"nonce": base64.StdEncoding.EncodeToString(nonce[:]),
		})
	case "/sign":
		s.handleSign(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *mockLPSigning) handleSign(w http.ResponseWriter, r *http.Request) {
	clientPublicKey := new([32]byte)
	requestNonce := new([24]byte)
	responseNonce := new([24]byte)
	for _, h := range []struct {
		name string
		dst  []byte
	}{
		{"X-Client-Public-Key", clientPublicKey[:]},
		{"X-Nonce", requestNonce[:]},
		{"X-Response-Nonce", responseNonce[:]},
	} {
		decoded, err := base64.StdEncoding.DecodeString(r.Header.Get(h.name))
		if err != nil || len(decoded) != len(h.dst) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		copy(h.dst, decoded)
	}
	body, _ := io.ReadAll(r.Body)
	ciphertext, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	plaintext, ok := box.Open(nil, ciphertext, requestNonce, clientPublicKey, s.servicePrivateKey)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var request mockSignRequest
	if err := json.Unmarshal(plaintext, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.signRequests = append(s.signRequests, request)
	s.mu.Unlock()

	status := http.StatusOK
	var response any
	signingKey := s.signingKeys[request.Fingerprint]
	message, err := base64.StdEncoding.DecodeString(request.Message)
	switch {
	case s.errorMessage != "":
		status = http.StatusBadRequest
		response = map[string]any{"error_list": []map[string]string{{"message": s.errorMessage}}}
	case signingKey == nil || err != nil:
		status = http.StatusBadRequest
		response = map[string]any{"error_list": []map[string]string{{"message": "unknown key"}}}
	default:
		armoredSignature, armoredPublicKey, err := signArmored(signingKey, message)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		response = map[string]string{
			"signed-message": base64.StdEncoding.EncodeToString(armoredSignature),
			"public-key":     base64.StdEncoding.EncodeToString(armoredPublicKey),
		}
	}
	responseBody, _ := json.Marshal(response)
	boxed := box.Seal(nil, responseBody, responseNonce, clientPublicKey, s.servicePrivateKey)
	w.Header().Set("Content-Type", "application/x-boxed-json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(boxed)))
}

func (s *mockLPSigning) requests() []mockSignRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]mockSignRequest(nil), s.signRequests...)
}

func signArmored(privateKey *rsa.PrivateKey, content []byte) (armoredSignature, armoredPublicKey []byte, err error) {
	sig := &packet.Signature{
		PubKeyAlgo:   packet.PubKeyAlgoRSA,
		Hash:         crypto.SHA512,
		CreationTime: time.Now(),
	}
	h := crypto.SHA512.New()
	h.Write(content)
	if err := sig.Sign(h, packet.NewRSAPrivateKey(time.Unix(1, 0), privateKey), &packet.Config{DefaultHash: crypto.SHA512}); err != nil {
		return nil, nil, err
	}
	armoredSignature, err = armorEncode("PGP SIGNATURE", sig.Serialize)
	if err != nil {
		return nil, nil, err
	}
	armoredPublicKey, err = armorEncode("PGP PUBLIC KEY BLOCK", packet.NewRSAPublicKey(time.Unix(1, 0), &privateKey.PublicKey).Serialize)
	if err != nil {
		return nil, nil, err
	}
	return armoredSignature, armoredPublicKey, nil
}

func armorEncode(blockType string, serialize func(io.Writer) error) ([]byte, error) {
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, blockType, nil)
	if err != nil {
		return nil, err
	}
	if err := serialize(w); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type lpsignkeymgrSuite struct {
	store     *assertstest.StoreStack
	brandAcct *asserts.Account

	devPrivKey    asserts.PrivateKey
	devRSAPrivKey *rsa.PrivateKey
	devAccKey     *asserts.AccountKey
	altPrivKey    asserts.PrivateKey
	altRSAPrivKey *rsa.PrivateKey
	altAccKey     *asserts.AccountKey

	service *mockLPSigning
	server  *httptest.Server

	dir        string
	configPath string
	cfg        map[string]any
	restoreEnv string
	hadEnv     bool
}

var _ = check.Suite(&lpsignkeymgrSuite{})

func (s *lpsignkeymgrSuite) SetUpSuite(c *check.C) {
	s.store = assertstest.NewStoreStack("trusted", nil)
	s.brandAcct = assertstest.NewAccount(s.store, "brand", map[string]any{
		"account-id": "brand-id",
	}, "")
	s.devPrivKey, s.devRSAPrivKey = assertstest.ReadPrivKey(assertstest.DevKey)
	s.devAccKey = assertstest.NewAccountKey(s.store, s.brandAcct, nil, s.devPrivKey.PublicKey(), "")
	s.altPrivKey, s.altRSAPrivKey = assertstest.GenerateKey(4096)
	s.altAccKey = assertstest.NewAccountKey(s.store, s.brandAcct, map[string]any{
		"name": "alt",
	}, s.altPrivKey.PublicKey(), "")
}

func (s *lpsignkeymgrSuite) SetUpTest(c *check.C) {
	s.service = newMockLPSigning(c, map[string]*rsa.PrivateKey{
		"DEVFPR": s.devRSAPrivKey,
		"ALTFPR": s.altRSAPrivKey,
	})
	s.server = httptest.NewServer(s.service)

	s.dir = c.MkDir()
	c.Assert(os.WriteFile(filepath.Join(s.dir, "dev.account-key"), asserts.Encode(s.devAccKey), 0644), check.IsNil)
	c.Assert(os.MkdirAll(filepath.Join(s.dir, "keys"), 0755), check.IsNil)
	altAccKeyPath := filepath.Join(s.dir, "keys", "alt.account-key")
	c.Assert(os.WriteFile(altAccKeyPath, asserts.Encode(s.altAccKey), 0644), check.IsNil)

	_, clientPrivateKey, err := box.GenerateKey(rand.Reader)
	c.Assert(err, check.IsNil)
	s.cfg = map[string]any{
		"base-url":           s.server.URL,
		"client-private-key": base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		"keys": []map[string]string{
			{"fingerprint": "DEVFPR", "account-key": "dev.account-key"},
			{"fingerprint": "ALTFPR", "account-key": altAccKeyPath},
		},
	}
	s.configPath = filepath.Join(s.dir, "config.json")
	s.writeConfig(c)

	s.restoreEnv, s.hadEnv = os.LookupEnv(configEnv)
	os.Setenv(configEnv, s.configPath)
}

func (s *lpsignkeymgrSuite) TearDownTest(c *check.C) {
	s.server.Close()
	if s.hadEnv {
		os.Setenv(configEnv, s.restoreEnv)
	} else {
		os.Unsetenv(configEnv)
	}
	os.Unsetenv(runMainEnv)
}

func (s *lpsignkeymgrSuite) writeConfig(c *check.C) {
	data, err := json.Marshal(s.cfg)
	c.Assert(err, check.IsNil)
	c.Assert(os.WriteFile(s.configPath, data, 0600), check.IsNil)
}

func (s *lpsignkeymgrSuite) run(c *check.C, stdin []byte, args ...string) ([]byte, error) {
	var stdout bytes.Buffer
	err := run(args, bytes.NewReader(stdin), &stdout)
	return stdout.Bytes(), err
}

func (s *lpsignkeymgrSuite) TestFeatures(c *check.C) {
	out, err := s.run(c, nil, "features")
	c.Assert(err, check.IsNil)
	c.Check(string(out), check.Equals, `{"public-keys":["DER"],"signing":["OPENPGP"]}`+"\n")
}

func (s *lpsignkeymgrSuite) TestKeyNames(c *check.C) {
	out, err := s.run(c, nil, "key-names")
	c.Assert(err, check.IsNil)
	c.Check(string(out), check.Equals, `{"key-names":["DEVFPR","ALTFPR"]}`+"\n")
}

func (s *lpsignkeymgrSuite) TestGetPublicKey(c *check.C) {
	for _, t := range []struct {
		fingerprint string
		pubKey      *rsa.PublicKey
		keyID       string
	}{
		{"DEVFPR", &s.devRSAPrivKey.PublicKey, s.devAccKey.PublicKeyID()},
		{"ALTFPR", &s.altRSAPrivKey.PublicKey, s.altAccKey.PublicKeyID()},
	} {
		out, err := s.run(c, nil, "get-public-key", "-f", "DER", "-k", t.fingerprint)
		c.Assert(err, check.IsNil)
		pub, err := x509.ParsePKIXPublicKey(out)
		c.Assert(err, check.IsNil)
		rsaPub, ok := pub.(*rsa.PublicKey)
		c.Assert(ok, check.Equals, true)
		c.Check(rsaPub.Equal(t.pubKey), check.Equals, true)
		c.Check(asserts.RSAPublicKey(rsaPub).ID(), check.Equals, t.keyID)
	}
}

func (s *lpsignkeymgrSuite) TestGetPublicKeyErrors(c *check.C) {
	for _, t := range []struct {
		args []string
		err  string
	}{
		{[]string{"-f", "DER", "-k", "OTHERFPR"}, `get-public-key: cannot find key "OTHERFPR": key not found`},
		{[]string{"-f", "DER"}, `get-public-key: cannot find key "": key not found`},
		{[]string{"-f", "PEM", "-k", "DEVFPR"}, `get-public-key: unsupported format "PEM"`},
		{[]string{"-k", "DEVFPR"}, `get-public-key: unsupported format ""`},
		{[]string{"-f", "DER", "-k", "DEVFPR", "extra"}, `get-public-key: unexpected arguments \["extra"\]`},
		{[]string{"-x"}, `get-public-key: flag provided but not defined: -x`},
	} {
		out, err := s.run(c, nil, append([]string{"get-public-key"}, t.args...)...)
		c.Check(err, check.ErrorMatches, t.err, check.Commentf("%v", t.args))
		c.Check(out, check.HasLen, 0)
	}
}

func (s *lpsignkeymgrSuite) TestSign(c *check.C) {
	content := []byte("content to sign")
	out, err := s.run(c, content, "sign", "-m", "OPENPGP", "-k", "ALTFPR")
	c.Assert(err, check.IsNil)

	pkt, err := packet.Read(bytes.NewReader(out))
	c.Assert(err, check.IsNil)
	sig, ok := pkt.(*packet.Signature)
	c.Assert(ok, check.Equals, true)
	h := sig.Hash.New()
	h.Write(content)
	pub := packet.NewRSAPublicKey(time.Unix(1, 0), &s.altRSAPrivKey.PublicKey)
	c.Check(pub.VerifySignature(h, sig), check.IsNil)

	reqs := s.service.requests()
	c.Assert(reqs, check.HasLen, 1)
	c.Check(reqs[0].KeyType, check.Equals, "OPENPGP")
	c.Check(reqs[0].Fingerprint, check.Equals, "ALTFPR")
	c.Check(reqs[0].Mode, check.Equals, "DETACHED")
	c.Check(reqs[0].Message, check.Equals, base64.StdEncoding.EncodeToString(content))
}

func (s *lpsignkeymgrSuite) TestSignErrors(c *check.C) {
	for _, t := range []struct {
		args []string
		err  string
	}{
		{[]string{"-m", "RSA-PKCS", "-k", "DEVFPR"}, `sign: unsupported signing mode "RSA-PKCS"`},
		{[]string{"-k", "DEVFPR"}, `sign: unsupported signing mode ""`},
		{[]string{"-m", "OPENPGP", "-k", "OTHERFPR"}, `cannot sign with lp-signing: no configured key with fingerprint "OTHERFPR": key not found`},
		{[]string{"-m", "OPENPGP", "-k", "DEVFPR", "extra"}, `sign: unexpected arguments \["extra"\]`},
	} {
		out, err := s.run(c, []byte("content"), append([]string{"sign"}, t.args...)...)
		c.Check(err, check.ErrorMatches, t.err, check.Commentf("%v", t.args))
		c.Check(out, check.HasLen, 0)
	}
	c.Check(s.service.requests(), check.HasLen, 0)
}

func (s *lpsignkeymgrSuite) TestSignServiceError(c *check.C) {
	s.service.errorMessage = "not authorized"
	out, err := s.run(c, []byte("content"), "sign", "-m", "OPENPGP", "-k", "DEVFPR")
	c.Check(err, check.ErrorMatches, `cannot call lp-signing /sign: not authorized`)
	c.Check(out, check.HasLen, 0)
}

func (s *lpsignkeymgrSuite) TestUsageAndUnsupportedCommand(c *check.C) {
	_, err := s.run(c, nil)
	c.Check(err, check.ErrorMatches, `usage: lpsignkeymgr .*`)
	_, err = s.run(c, nil, "key-ids")
	c.Check(err, check.ErrorMatches, `unsupported command "key-ids"`)
	_, err = s.run(c, nil, "features", "extra")
	c.Check(err, check.ErrorMatches, `features: unexpected arguments \["extra"\]`)
	_, err = s.run(c, nil, "key-names", "extra")
	c.Check(err, check.ErrorMatches, `key-names: unexpected arguments \["extra"\]`)
}

func (s *lpsignkeymgrSuite) TestConfigEnvNotSet(c *check.C) {
	os.Unsetenv(configEnv)
	_, err := s.run(c, nil, "features")
	c.Check(err, check.ErrorMatches, `cannot load configuration: LPSIGNKEYMGR_CONFIG is not set`)
}

func (s *lpsignkeymgrSuite) TestConfigMissing(c *check.C) {
	os.Setenv(configEnv, filepath.Join(s.dir, "missing.json"))
	_, err := s.run(c, nil, "features")
	c.Check(err, check.ErrorMatches, `cannot load configuration: open .*/missing.json: no such file or directory`)
}

func (s *lpsignkeymgrSuite) TestConfigPermissions(c *check.C) {
	for _, mode := range []os.FileMode{0640, 0604, 0644} {
		c.Assert(os.Chmod(s.configPath, mode), check.IsNil)
		_, err := s.run(c, nil, "features")
		c.Check(err, check.ErrorMatches, fmt.Sprintf(`cannot load configuration ".*/config.json": must not be accessible by group or others \(mode %#o\)`, mode))
	}
}

func (s *lpsignkeymgrSuite) TestConfigErrors(c *check.C) {
	notAccountKeyPath := filepath.Join(s.dir, "account.assert")
	c.Assert(os.WriteFile(notAccountKeyPath, asserts.Encode(s.brandAcct), 0644), check.IsNil)
	garbagePath := filepath.Join(s.dir, "garbage.assert")
	c.Assert(os.WriteFile(garbagePath, []byte("garbage"), 0644), check.IsNil)

	for _, t := range []struct {
		mutate func(cfg map[string]any)
		err    string
	}{
		{func(cfg map[string]any) { cfg["unknown"] = "x" }, `cannot decode configuration ".*/config.json": json: unknown field "unknown"`},
		{func(cfg map[string]any) { cfg["keys"] = []map[string]string{{"fingerprint": "DEVFPR"}} }, `cannot load configuration: missing account-key for fingerprint "DEVFPR"`},
		{func(cfg map[string]any) {
			cfg["keys"] = []map[string]string{{"fingerprint": "DEVFPR", "account-key": "nonexistent"}}
		}, `cannot read account-key assertion: open .*/nonexistent: no such file or directory`},
		{func(cfg map[string]any) {
			cfg["keys"] = []map[string]string{{"fingerprint": "DEVFPR", "account-key": notAccountKeyPath}}
		}, `cannot use ".*/account.assert": expected account-key assertion, got "account"`},
		{func(cfg map[string]any) {
			cfg["keys"] = []map[string]string{{"fingerprint": "DEVFPR", "account-key": garbagePath}}
		}, `cannot decode account-key assertion ".*/garbage.assert": .*`},
		{func(cfg map[string]any) {
			cfg["keys"] = []map[string]string{{"account-key": "dev.account-key"}}
		}, `cannot create lp-signing backend: missing fingerprint for account-key .*`},
		{func(cfg map[string]any) {
			cfg["keys"] = []map[string]string{
				{"fingerprint": "DEVFPR", "account-key": "dev.account-key"},
				{"fingerprint": "DEVFPR", "account-key": "keys/alt.account-key"},
			}
		}, `cannot create lp-signing backend: duplicate fingerprint "DEVFPR"`},
		{func(cfg map[string]any) { cfg["keys"] = []map[string]string{} }, `cannot create lp-signing backend: no signing keys configured`},
		{func(cfg map[string]any) { cfg["client-private-key"] = "short" }, `cannot create lp-signing backend: cannot decode client private key: .*`},
		{func(cfg map[string]any) { delete(cfg, "base-url") }, `cannot create lp-signing backend: missing base URL`},
	} {
		saved := make(map[string]any, len(s.cfg))
		for k, v := range s.cfg {
			saved[k] = v
		}
		t.mutate(s.cfg)
		s.writeConfig(c)
		_, err := s.run(c, nil, "features")
		c.Check(err, check.ErrorMatches, t.err)
		s.cfg = saved
	}
	c.Assert(os.WriteFile(s.configPath, []byte("{"), 0600), check.IsNil)
	_, err := s.run(c, nil, "features")
	c.Check(err, check.ErrorMatches, `cannot decode configuration ".*/config.json": unexpected EOF`)
}

func (s *lpsignkeymgrSuite) TestExternalKeypairManagerIntegration(c *check.C) {
	os.Setenv(runMainEnv, "1")
	kmgr, err := asserts.NewExternalKeypairManager(os.Args[0])
	c.Assert(err, check.IsNil)

	keys, err := kmgr.List()
	c.Assert(err, check.IsNil)
	c.Check(keys, check.DeepEquals, []asserts.ExternalKeyInfo{
		{Name: "DEVFPR", ID: s.devAccKey.PublicKeyID()},
		{Name: "ALTFPR", ID: s.altAccKey.PublicKeyID()},
	})

	exported, err := kmgr.Export("ALTFPR")
	c.Assert(err, check.IsNil)
	expected, err := asserts.EncodePublicKey(s.altPrivKey.PublicKey())
	c.Assert(err, check.IsNil)
	c.Check(exported, check.DeepEquals, expected)

	byName, err := kmgr.GetByName("DEVFPR")
	c.Assert(err, check.IsNil)
	c.Check(byName.PublicKey().ID(), check.Equals, s.devAccKey.PublicKeyID())

	_, err = kmgr.GetByName("OTHERFPR")
	c.Check(err, check.ErrorMatches, `cannot find external key pair: .*key not found.*`)

	signDB, err := asserts.OpenDatabase(&asserts.DatabaseConfig{KeypairManager: kmgr})
	c.Assert(err, check.IsNil)
	checkDB, err := asserts.OpenDatabase(&asserts.DatabaseConfig{
		Backstore: asserts.NewMemoryBackstore(),
		Trusted:   s.store.Trusted,
	})
	c.Assert(err, check.IsNil)
	c.Assert(checkDB.Add(s.store.StoreAccountKey("")), check.IsNil)
	c.Assert(checkDB.Add(s.brandAcct), check.IsNil)
	c.Assert(checkDB.Add(s.devAccKey), check.IsNil)
	c.Assert(checkDB.Add(s.altAccKey), check.IsNil)

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
	for _, keyID := range []string{s.devAccKey.PublicKeyID(), s.altAccKey.PublicKeyID()} {
		a, err := signDB.Sign(asserts.ModelType, modelHeaders, nil, keyID)
		c.Assert(err, check.IsNil)
		c.Check(checkDB.Check(a), check.IsNil)
	}

	reqs := s.service.requests()
	c.Assert(reqs, check.HasLen, 2)
	c.Check(reqs[0].Fingerprint, check.Equals, "DEVFPR")
	c.Check(reqs[1].Fingerprint, check.Equals, "ALTFPR")
}
