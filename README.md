# asserts-lp-sign

`asserts-lp-sign` is a Go client library for Canonical's Launchpad signing
service (lp-signing). It implements a sign-only [snapd `asserts`](https://github.com/snapcore/snapd)
external keypair-manager backend (`KeypairMgrBackend`): private keys remain
server-side and the library only requests detached signatures over lp-signing's
boxed HTTP API.

It is consumed as a Go module:

    require github.com/canonical/asserts-lp-sign v0.1.0

The package identifier is `assertslpsign` (Go identifiers cannot contain
hyphens): `import "github.com/canonical/asserts-lp-sign"` then reference
`assertslpsign.NewKeypairMgrBackend`.

See `cmd/lpsigndemo` for a complete example wiring `NewKeypairMgrBackend` into
`asserts.NewExternalKeypairManagerWithBackend` and signing an assertion through an
`asserts.Database`.

## Development

Requires a Go toolchain (≥ 1.20) on PATH, or the Go snap at `/snap/bin/go` — the
Makefile autodetects both; override with `make GO=<path>` if needed. Go ≥ 1.20
builds and tests the library (`go build ./...`, `go test ./...`); `make lint`
and `make test` additionally install the pinned staticcheck v0.7.0, whose build
requires Go ≥ 1.25 — toolchains ≥ 1.21 fetch that automatically
(`GOTOOLCHAIN=auto` is the default).

    make test     # lint + run the test suite (gocheck)
    make lint     # gofmt, go vet, staticcheck
    make fmt      # auto-format

## License

GNU General Public License v3 — see `LICENSE`. Copyright (C) 2026 Canonical Ltd.
