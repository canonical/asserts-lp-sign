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
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/crypto/nacl/box"
	//lint:ignore SA1019 openpgp interop is required to talk to lp-signing; snapd itself uses this package
	"golang.org/x/crypto/openpgp/armor"
	//lint:ignore SA1019 openpgp interop is required to talk to lp-signing; snapd itself uses this package
	"golang.org/x/crypto/openpgp/packet"

	"github.com/snapcore/snapd/asserts"
)

const (
	lpSigningKeyTypeOpenPGP = "OPENPGP"
	lpSigningModeDetached   = "DETACHED"
	lpSigningMessageName    = "(assertion digest)"
)

// Config describes how to connect to the Launchpad signing service.
type Config struct {
	BaseURL          string
	ClientPrivateKey string
	Keys             []KeyConfig
}

// KeyConfig maps one account-key assertion to the Launchpad fingerprint used for signing.
type KeyConfig struct {
	AccountKey  *asserts.AccountKey
	Fingerprint string
}

func newLoadedKey(keyCfg KeyConfig) (*asserts.ExtKeypairMgrLoadedKey, error) {
	if keyCfg.AccountKey == nil {
		return nil, fmt.Errorf("cannot create lp-signing backend: missing account-key assertion")
	}
	if keyCfg.Fingerprint == "" {
		return nil, fmt.Errorf("cannot create lp-signing backend: missing fingerprint for account-key %q", keyCfg.AccountKey.PublicKeyID())
	}
	publicKey, err := asserts.DecodePublicKey(keyCfg.AccountKey.Body())
	if err != nil {
		return nil, fmt.Errorf("cannot create lp-signing backend: cannot decode account-key public key %q: %v", keyCfg.AccountKey.PublicKeyID(), err)
	}
	if publicKey.ID() != keyCfg.AccountKey.PublicKeyID() {
		return nil, fmt.Errorf("cannot create lp-signing backend: account-key body does not match public key id %q", keyCfg.AccountKey.PublicKeyID())
	}
	return &asserts.ExtKeypairMgrLoadedKey{
		Name:      keyCfg.Fingerprint,
		KeyHandle: keyCfg.Fingerprint,
		PublicKey: publicKey,
	}, nil
}

// KeypairMgrBackend is a sign-only asserts external keypair manager backend backed by lp-signing.
type KeypairMgrBackend struct {
	baseURL          string
	httpClient       *http.Client
	clientPublicKey  [32]byte
	clientPrivateKey [32]byte

	mu               sync.Mutex
	servicePublicKey *[32]byte
	serviceSharedKey *[32]byte

	loadedKeysByID     map[string]*asserts.ExtKeypairMgrLoadedKey
	loadedKeysByHandle map[string]*asserts.ExtKeypairMgrLoadedKey
}

// NewKeypairMgrBackend creates a sign-only lp-signing backend from constructor-supplied configuration.
func NewKeypairMgrBackend(cfg Config) (*KeypairMgrBackend, error) {
	baseURL, err := normalizeBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	clientPrivateKey, clientPublicKey, err := decodeClientPrivateKey(cfg.ClientPrivateKey)
	if err != nil {
		return nil, err
	}
	if len(cfg.Keys) == 0 {
		return nil, fmt.Errorf("cannot create lp-signing backend: no signing keys configured")
	}

	loadedKeysByID := make(map[string]*asserts.ExtKeypairMgrLoadedKey, len(cfg.Keys))
	loadedKeysByHandle := make(map[string]*asserts.ExtKeypairMgrLoadedKey, len(cfg.Keys))
	for _, keyCfg := range cfg.Keys {
		loadedKey, err := newLoadedKey(keyCfg)
		if err != nil {
			return nil, err
		}
		keyID := loadedKey.PublicKey.ID()
		if _, found := loadedKeysByID[keyID]; found {
			return nil, fmt.Errorf("cannot create lp-signing backend: duplicate key id %q", keyID)
		}
		if _, found := loadedKeysByHandle[loadedKey.KeyHandle]; found {
			return nil, fmt.Errorf("cannot create lp-signing backend: duplicate fingerprint %q", loadedKey.KeyHandle)
		}
		loadedKeysByID[keyID] = loadedKey
		loadedKeysByHandle[loadedKey.KeyHandle] = loadedKey
	}

	return &KeypairMgrBackend{
		baseURL:            baseURL,
		httpClient:         http.DefaultClient,
		clientPublicKey:    clientPublicKey,
		clientPrivateKey:   clientPrivateKey,
		loadedKeysByID:     loadedKeysByID,
		loadedKeysByHandle: loadedKeysByHandle,
	}, nil
}

func (b *KeypairMgrBackend) CheckFeatures() (asserts.ExtKeypairMgrSigning, error) {
	return asserts.ExtKeypairMgrSigningOpenPGP, nil
}

func (b *KeypairMgrBackend) LoadByID(keyID string) (*asserts.ExtKeypairMgrLoadedKey, error) {
	loadedKey := b.loadedKeysByID[keyID]
	if loadedKey == nil {
		return nil, &keyNotFoundError{msg: "missing key"}
	}
	return loadedKey, nil
}

// LoadByCanonicalFingerprint loads a configured key by its canonical fingerprint.
func (b *KeypairMgrBackend) LoadByCanonicalFingerprint(fingerprint string) (*asserts.ExtKeypairMgrLoadedKey, error) {
	loadedKey := b.loadedKeysByHandle[fingerprint]
	if loadedKey == nil {
		return nil, &keyNotFoundError{msg: "missing key"}
	}
	return loadedKey, nil
}

type keyNotFoundError struct {
	msg string
}

func (e *keyNotFoundError) Error() string {
	return e.msg
}

func (b *KeypairMgrBackend) RSAPKCSSign(keyHandle string, prepared []byte) ([]byte, error) {
	return nil, fmt.Errorf("internal error: lp-signing backend does not support RSA-PKCS signing")
}

func (b *KeypairMgrBackend) Sign(keyHandle string, content []byte) ([]byte, error) {
	loadedKey := b.loadedKeysByHandle[keyHandle]
	if loadedKey == nil {
		return nil, &keyNotFoundError{msg: "missing key"}
	}

	signedMessage, decodedPublicKey, err := b.signDetached(loadedKey, content)
	if err != nil {
		return nil, err
	}
	if decodedPublicKey.ID() != loadedKey.PublicKey.ID() {
		return nil, fmt.Errorf("cannot sign with lp-signing: service used unexpected key with id %q, expected %q", decodedPublicKey.ID(), loadedKey.PublicKey.ID())
	}
	return decodeArmoredSignature(signedMessage)
}

type lpSigningSignRequest struct {
	KeyType     string `json:"key-type"`
	Fingerprint string `json:"fingerprint"`
	MessageName string `json:"message-name"`
	Message     string `json:"message"`
	Mode        string `json:"mode"`
}

type lpSigningSignResponse struct {
	PublicKey     string `json:"public-key"`
	SignedMessage string `json:"signed-message"`
}

type lpSigningServiceKeyResponse struct {
	ServiceKey string `json:"service-key"`
}

type lpSigningNonceResponse struct {
	Nonce string `json:"nonce"`
}

func (b *KeypairMgrBackend) signDetached(loadedKey *asserts.ExtKeypairMgrLoadedKey, content []byte) ([]byte, asserts.PublicKey, error) {
	responseBody, err := b.boxedPost("/sign", lpSigningSignRequest{
		KeyType:     lpSigningKeyTypeOpenPGP,
		Fingerprint: loadedKey.KeyHandle,
		MessageName: lpSigningMessageName,
		Message:     base64.StdEncoding.EncodeToString(content),
		Mode:        lpSigningModeDetached,
	})
	if err != nil {
		return nil, nil, err
	}

	var response lpSigningSignResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, nil, fmt.Errorf("cannot decode lp-signing sign response: %v", err)
	}
	if response.SignedMessage == "" {
		return nil, nil, fmt.Errorf("cannot decode lp-signing sign response: missing signed-message")
	}
	signedMessage, err := base64.StdEncoding.DecodeString(response.SignedMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot decode lp-signing sign response: %v", err)
	}
	if response.PublicKey == "" {
		return nil, nil, fmt.Errorf("cannot decode lp-signing sign response: missing public-key")
	}
	armoredPublicKey, err := base64.StdEncoding.DecodeString(response.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot decode lp-signing sign response public key: %v", err)
	}
	decodedPublicKey, err := decodeArmoredPublicKey(armoredPublicKey)
	if err != nil {
		return nil, nil, err
	}
	return signedMessage, decodedPublicKey, nil
}

func decodeArmoredPublicKey(armoredPublicKey []byte) (asserts.PublicKey, error) {
	block, err := armor.Decode(bytes.NewReader(armoredPublicKey))
	if err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing sign response public key: %v", err)
	}
	if block.Type != "PGP PUBLIC KEY BLOCK" {
		return nil, fmt.Errorf("cannot decode lp-signing sign response public key: unexpected block type %q", block.Type)
	}
	decodedPublicKey, err := io.ReadAll(block.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing sign response public key: %v", err)
	}

	packetReader := packet.NewReader(bytes.NewReader(decodedPublicKey))
	pkt, err := packetReader.Next()
	if err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing sign response public key: %v", err)
	}
	pgpPublicKey, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot decode lp-signing sign response public key: unexpected OpenPGP packet %T", pkt)
	}
	rsaPublicKey, ok := pgpPublicKey.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot decode lp-signing sign response public key: unsupported OpenPGP public key type %T", pgpPublicKey.PublicKey)
	}
	return asserts.RSAPublicKey(rsaPublicKey), nil
}

func decodeArmoredSignature(armoredSignature []byte) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader(armoredSignature))
	if err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing armored signature: %v", err)
	}
	if block.Type != "PGP SIGNATURE" {
		return nil, fmt.Errorf("cannot decode lp-signing armored signature: unexpected block type %q", block.Type)
	}
	rawSignature, err := io.ReadAll(block.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing armored signature: %v", err)
	}
	return rawSignature, nil
}

func (b *KeypairMgrBackend) boxedPost(path string, payload any) ([]byte, error) {
	serviceSharedKey, err := b.getServiceSharedKey()
	if err != nil {
		return nil, err
	}
	nonce, err := b.getNonce()
	if err != nil {
		return nil, err
	}
	responseNonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("cannot encode lp-signing request: %v", err)
	}
	encryptedRequest := sealBox(plaintext, nonce, serviceSharedKey)
	request, err := http.NewRequest(http.MethodPost, b.baseURL+path, bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(encryptedRequest))))
	if err != nil {
		return nil, fmt.Errorf("cannot create lp-signing request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-boxed-json")
	request.Header.Set("X-Client-Public-Key", base64.StdEncoding.EncodeToString(b.clientPublicKey[:]))
	request.Header.Set("X-Nonce", base64.StdEncoding.EncodeToString(nonce[:]))
	request.Header.Set("X-Response-Nonce", base64.StdEncoding.EncodeToString(responseNonce[:]))

	response, err := b.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("cannot call lp-signing %s: %v", path, err)
	}
	defer response.Body.Close()

	encryptedResponse, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read lp-signing %s response: %v", path, err)
	}
	boxedResponse, err := base64.StdEncoding.DecodeString(string(encryptedResponse))
	if err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing %s response: %v", path, err)
	}
	plaintextResponse, ok := openBox(boxedResponse, responseNonce, serviceSharedKey)
	if !ok {
		return nil, fmt.Errorf("cannot decrypt lp-signing %s response", path)
	}
	if response.StatusCode >= 400 {
		return nil, decodeAPIError(path, plaintextResponse, response.StatusCode)
	}
	return plaintextResponse, nil
}

func (b *KeypairMgrBackend) getServiceSharedKey() (*[32]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.serviceSharedKey != nil {
		return b.serviceSharedKey, nil
	}
	response, err := b.httpClient.Get(b.baseURL + "/service-key")
	if err != nil {
		return nil, fmt.Errorf("cannot fetch lp-signing service key: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot fetch lp-signing service key: unexpected status %d", response.StatusCode)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch lp-signing service key: %v", err)
	}
	var serviceKeyResponse lpSigningServiceKeyResponse
	if err := json.Unmarshal(responseBody, &serviceKeyResponse); err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing service key response: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(serviceKeyResponse.ServiceKey)
	if err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing service key: %v", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("cannot decode lp-signing service key: expected 32 bytes, got %d", len(decoded))
	}
	servicePublicKey := new([32]byte)
	copy(servicePublicKey[:], decoded)
	b.servicePublicKey = servicePublicKey
	serviceSharedKey := new([32]byte)
	box.Precompute(serviceSharedKey, servicePublicKey, &b.clientPrivateKey)
	b.serviceSharedKey = serviceSharedKey
	return serviceSharedKey, nil
}

func (b *KeypairMgrBackend) getNonce() (*[24]byte, error) {
	response, err := b.httpClient.Post(b.baseURL+"/nonce", "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch lp-signing nonce: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("cannot fetch lp-signing nonce: unexpected status %d", response.StatusCode)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch lp-signing nonce: %v", err)
	}
	var nonceResponse lpSigningNonceResponse
	if err := json.Unmarshal(responseBody, &nonceResponse); err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing nonce response: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(nonceResponse.Nonce)
	if err != nil {
		return nil, fmt.Errorf("cannot decode lp-signing nonce: %v", err)
	}
	if len(decoded) != 24 {
		return nil, fmt.Errorf("cannot decode lp-signing nonce: expected 24 bytes, got %d", len(decoded))
	}
	nonce := new([24]byte)
	copy(nonce[:], decoded)
	return nonce, nil
}
func decodeAPIError(path string, plaintextResponse []byte, statusCode int) error {
	var apiErr struct {
		ErrorList []struct {
			Message string `json:"message"`
		} `json:"error_list"`
	}
	if err := json.Unmarshal(plaintextResponse, &apiErr); err == nil && len(apiErr.ErrorList) > 0 && apiErr.ErrorList[0].Message != "" {
		return fmt.Errorf("cannot call lp-signing %s: %s", path, apiErr.ErrorList[0].Message)
	}
	return fmt.Errorf("cannot call lp-signing %s: unexpected status %d", path, statusCode)
}

func normalizeBaseURL(rawBaseURL string) (string, error) {
	if rawBaseURL == "" {
		return "", fmt.Errorf("cannot create lp-signing backend: missing base URL")
	}
	parsed, err := url.Parse(rawBaseURL)
	if err != nil {
		return "", fmt.Errorf("cannot create lp-signing backend: invalid base URL: %v", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("cannot create lp-signing backend: invalid base URL %q", rawBaseURL)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func decodeClientPrivateKey(encoded string) ([32]byte, [32]byte, error) {
	var privateKey [32]byte
	var publicKey [32]byte
	if encoded == "" {
		return privateKey, publicKey, fmt.Errorf("cannot create lp-signing backend: missing client private key")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return privateKey, publicKey, fmt.Errorf("cannot create lp-signing backend: cannot decode client private key: %v", err)
	}
	if len(decoded) != len(privateKey) {
		return privateKey, publicKey, fmt.Errorf("cannot create lp-signing backend: client private key must be %d bytes, got %d", len(privateKey), len(decoded))
	}
	copy(privateKey[:], decoded)
	derivedPublicKey, err := x25519PublicKey(privateKey)
	if err != nil {
		return privateKey, publicKey, fmt.Errorf("cannot create lp-signing backend: cannot derive client public key: %v", err)
	}
	publicKey = derivedPublicKey
	return privateKey, publicKey, nil
}

func sealBox(message []byte, nonce *[24]byte, sharedKey *[32]byte) []byte {
	return box.SealAfterPrecomputation(nil, message, nonce, sharedKey)
}

func openBox(boxed []byte, nonce *[24]byte, sharedKey *[32]byte) ([]byte, bool) {
	return box.OpenAfterPrecomputation(nil, boxed, nonce, sharedKey)
}

func x25519PublicKey(privateKey [32]byte) ([32]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privateKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	var publicKey [32]byte
	copy(publicKey[:], priv.PublicKey().Bytes())
	return publicKey, nil
}

func randomNonce() (*[24]byte, error) {
	responseNonce := new([24]byte)
	if _, err := rand.Read(responseNonce[:]); err != nil {
		return nil, fmt.Errorf("cannot generate lp-signing response nonce: %v", err)
	}
	return responseNonce, nil
}
