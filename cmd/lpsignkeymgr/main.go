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

// Command lpsignkeymgr is a snapd external keypair manager (see
// SNAPD_EXT_KEYMGR) that signs via lp-signing.
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	//lint:ignore SA1019 openpgp interop is required to decode snapd public keys; snapd itself uses this package
	"golang.org/x/crypto/openpgp/packet"

	assertslpsign "github.com/canonical/asserts-lp-sign"
	"github.com/snapcore/snapd/asserts"
)

const configEnv = "LPSIGNKEYMGR_CONFIG"

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "lpsignkeymgr: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: lpsignkeymgr features|key-names|get-public-key|sign [options]")
	}
	cmd, cmdArgs := args[0], args[1:]
	switch cmd {
	case "features", "key-names", "get-public-key", "sign":
	default:
		return fmt.Errorf("unsupported command %q", cmd)
	}

	km, err := loadKeyMgr(os.Getenv(configEnv))
	if err != nil {
		return err
	}

	switch cmd {
	case "features":
		return km.features(cmdArgs, stdout)
	case "key-names":
		return km.keyNames(cmdArgs, stdout)
	case "get-public-key":
		return km.getPublicKey(cmdArgs, stdout)
	default:
		return km.sign(cmdArgs, stdin, stdout)
	}
}

type config struct {
	BaseURL          string      `json:"base-url"`
	ClientPrivateKey string      `json:"client-private-key"`
	Keys             []keyConfig `json:"keys"`
}

type keyConfig struct {
	Fingerprint string `json:"fingerprint"`
	// AccountKey is the path to an account-key assertion file, relative
	// paths are resolved against the configuration file directory.
	AccountKey string `json:"account-key"`
}

type keyMgr struct {
	backend      *assertslpsign.KeypairMgrBackend
	fingerprints []string
	accountKeys  map[string]*asserts.AccountKey
}

func loadKeyMgr(configPath string) (*keyMgr, error) {
	if configPath == "" {
		return nil, fmt.Errorf("cannot load configuration: %s is not set", configEnv)
	}
	cfg, err := readConfig(configPath)
	if err != nil {
		return nil, err
	}

	configDir := filepath.Dir(configPath)
	km := &keyMgr{
		accountKeys: make(map[string]*asserts.AccountKey, len(cfg.Keys)),
	}
	backendKeys := make([]assertslpsign.KeyConfig, 0, len(cfg.Keys))
	for _, keyCfg := range cfg.Keys {
		if keyCfg.AccountKey == "" {
			return nil, fmt.Errorf("cannot load configuration: missing account-key for fingerprint %q", keyCfg.Fingerprint)
		}
		accountKeyPath := keyCfg.AccountKey
		if !filepath.IsAbs(accountKeyPath) {
			accountKeyPath = filepath.Join(configDir, accountKeyPath)
		}
		accountKey, err := readAccountKey(accountKeyPath)
		if err != nil {
			return nil, err
		}
		backendKeys = append(backendKeys, assertslpsign.KeyConfig{
			AccountKey:  accountKey,
			Fingerprint: keyCfg.Fingerprint,
		})
		km.fingerprints = append(km.fingerprints, keyCfg.Fingerprint)
		km.accountKeys[keyCfg.Fingerprint] = accountKey
	}

	km.backend, err = assertslpsign.NewKeypairMgrBackend(assertslpsign.Config{
		BaseURL:          cfg.BaseURL,
		ClientPrivateKey: cfg.ClientPrivateKey,
		Keys:             backendKeys,
	})
	if err != nil {
		return nil, err
	}
	return km, nil
}

func readConfig(configPath string) (*config, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load configuration: %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot load configuration: %v", err)
	}
	// the configuration holds the lp-signing client private key
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("cannot load configuration %q: must not be accessible by group or others (mode %#o)", configPath, perm)
	}

	var cfg config
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("cannot decode configuration %q: %v", configPath, err)
	}
	return &cfg, nil
}

func readAccountKey(path string) (*asserts.AccountKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read account-key assertion: %v", err)
	}
	a, err := asserts.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode account-key assertion %q: %v", path, err)
	}
	accountKey, ok := a.(*asserts.AccountKey)
	if !ok {
		return nil, fmt.Errorf("cannot use %q: expected account-key assertion, got %q", path, a.Type().Name)
	}
	return accountKey, nil
}

func (km *keyMgr) features(args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("features: unexpected arguments %q", args)
	}
	return json.NewEncoder(stdout).Encode(map[string][]string{
		"signing":     {"OPENPGP"},
		"public-keys": {"DER"},
	})
}

func (km *keyMgr) keyNames(args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("key-names: unexpected arguments %q", args)
	}
	return json.NewEncoder(stdout).Encode(map[string][]string{
		"key-names": km.fingerprints,
	})
}

func (km *keyMgr) getPublicKey(args []string, stdout io.Writer) error {
	fs := newFlagSet("get-public-key")
	format := fs.String("f", "", "public key output format")
	keyName := fs.String("k", "", "key name")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *format != "DER" {
		return fmt.Errorf("get-public-key: unsupported format %q", *format)
	}
	accountKey := km.accountKeys[*keyName]
	if accountKey == nil {
		return fmt.Errorf("get-public-key: cannot find key %q: %w", *keyName, assertslpsign.ErrKeyNotFound)
	}
	der, err := publicKeyDER(accountKey)
	if err != nil {
		return err
	}
	_, err = stdout.Write(der)
	return err
}

// publicKeyDER converts the snapd v1 encoded public key in an account-key body to PKIX DER.
func publicKeyDER(accountKey *asserts.AccountKey) ([]byte, error) {
	// TODO: have a helper in asserts for this
	encoded, err := base64.StdEncoding.DecodeString(string(accountKey.Body()))
	if err != nil {
		return nil, fmt.Errorf("cannot decode account-key %q public key: %v", accountKey.PublicKeyID(), err)
	}
	if len(encoded) == 0 || encoded[0] != 0x1 {
		return nil, fmt.Errorf("cannot decode account-key %q public key: unsupported format", accountKey.PublicKeyID())
	}
	pkt, err := packet.Read(bytes.NewReader(encoded[1:]))
	if err != nil {
		return nil, fmt.Errorf("cannot decode account-key %q public key: %v", accountKey.PublicKeyID(), err)
	}
	pgpPublicKey, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot decode account-key %q public key: unexpected OpenPGP packet %T", accountKey.PublicKeyID(), pkt)
	}
	rsaPublicKey, ok := pgpPublicKey.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot decode account-key %q public key: unsupported public key type %T", accountKey.PublicKeyID(), pgpPublicKey.PublicKey)
	}
	return x509.MarshalPKIXPublicKey(rsaPublicKey)
}

func (km *keyMgr) sign(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := newFlagSet("sign")
	mode := fs.String("m", "", "signing mode")
	keyName := fs.String("k", "", "key name")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *mode != "OPENPGP" {
		return fmt.Errorf("sign: unsupported signing mode %q", *mode)
	}
	content, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("sign: cannot read content to sign: %v", err)
	}
	signature, err := km.backend.Sign(*keyName, content)
	if err != nil {
		return err
	}
	_, err = stdout.Write(signature)
	return err
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%s: %v", fs.Name(), err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s: unexpected arguments %q", fs.Name(), fs.Args())
	}
	return nil
}
