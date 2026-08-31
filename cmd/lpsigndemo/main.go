// -*- Mode: Go; indent-tabs-mode: t -*-

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/canonical/asserts-lp-sign"
	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/systestkeys"
)

const (
	lpSigningBaseURL     = "http://0.0.0.0:8000"
	lpSigningFingerprint = "93E0E2DF59197703F69940B9DDA0945FBDDE6F8D"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "lpsigndemo: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: %s <encoded-client-private-key>", os.Args[0])
	}
	clientPrivateKey := strings.TrimSpace(os.Args[1])
	if clientPrivateKey == "" {
		return fmt.Errorf("cannot use empty lp-signing client private key argument")
	}

	accountKey, ok := systestkeys.TestStoreAccountKey.(*asserts.AccountKey)
	if !ok {
		return fmt.Errorf("internal error: unexpected store account-key assertion type %T", systestkeys.TestStoreAccountKey)
	}

	backend, err := assertslpsign.NewKeypairMgrBackend(assertslpsign.Config{
		BaseURL:          lpSigningBaseURL,
		ClientPrivateKey: clientPrivateKey,
		Keys: []assertslpsign.KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: lpSigningFingerprint,
		}},
	})
	if err != nil {
		return fmt.Errorf("cannot create lp-signing backend: %w", err)
	}

	keypairMgr, err := asserts.NewExternalKeypairManagerWithBackend(backend, asserts.ExtKeypairMgrConfig{
		SigningWith: "lp-signing",
		KeyStore:    "lp-signing",
	})
	if err != nil {
		return fmt.Errorf("cannot create external keypair manager: %w", err)
	}

	db, err := asserts.OpenDatabase(&asserts.DatabaseConfig{
		Backstore:      asserts.NewMemoryBackstore(),
		Trusted:        systestkeys.Trusted,
		KeypairManager: keypairMgr,
	})
	if err != nil {
		return fmt.Errorf("cannot open assertion database: %w", err)
	}

	if err := db.Add(systestkeys.TestStoreAccountKey); err != nil {
		return fmt.Errorf("cannot add store account-key assertion: %w", err)
	}

	headers := map[string]any{
		"authority-id": "testrootorg",
		"account-id":   "signdemo-account",
		"display-name": "Sign Demo Account",
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"username":     "signdemo",
		"validation":   "unproven",
	}

	signed, err := db.Sign(asserts.AccountType, headers, nil, systestkeys.TestStoreKeyID)
	if err != nil {
		return fmt.Errorf("cannot sign account assertion: %w", err)
	}

	if err := db.Check(signed); err != nil {
		return fmt.Errorf("cannot validate signed assertion: %w", err)
	}

	_, err = fmt.Print(string(asserts.Encode(signed)))
	if err != nil {
		return fmt.Errorf("cannot print signed assertion: %w", err)
	}

	return nil
}
