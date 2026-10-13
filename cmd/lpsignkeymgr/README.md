# lpsignkeymgr

`lpsignkeymgr` is an external keypair manager executable for snapd tooling
(`snap sign`, `snap keys`, `snap export-key`, ...) signing via lp-signing. Point
`SNAPD_EXT_KEYMGR` at it and `LPSIGNKEYMGR_CONFIG` at a JSON configuration file:

    {
      "base-url": "https://signing.example.com",
      "client-private-key": "<base64 X25519 client private key>",
      "keys": [
        {"fingerprint": "93E0E2DF59197703F69940B9DDA0945FBDDE6F8D", "account-key": "store.account-key"}
      ]
    }

`account-key` is the path to the account-key assertion for the key (relative
paths are resolved against the configuration file directory). The configuration
holds the client private key and must not be accessible by group or others.

Key names are the lp-signing fingerprints:

    SNAPD_EXT_KEYMGR=/path/to/lpsignkeymgr LPSIGNKEYMGR_CONFIG=/path/to/config.json \
      snap sign -k 93E0E2DF59197703F69940B9DDA0945FBDDE6F8D < headers.json

Only signing with existing lp-signing keys is supported (`OPENPGP` signing
mode); keys cannot be created, imported or deleted. Key listing and public key
export are served from the configured account-key assertions. The snapd tooling
must support the external keypair manager `OPENPGP` signing mode.
