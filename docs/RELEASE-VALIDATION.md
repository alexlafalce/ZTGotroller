# Release validation

The initial controller milestone was closed on July 28, 2026 with:

- `go test -race ./...`
- `go vet ./...`
- `govulncheck ./...`
- a clean build using Go `1.25.12`
- an unmodified ZeroTier One 1.14.2 interoperability run
- an unmodified current MPL `origin/dev` interoperability run
- mixed-version peer-to-peer ICMP with zero packet loss
- inspection of every linked Go module license

## Security boundary

- The administrative API requires a bearer token. Keep it bound to loopback or
  place it behind TLS and a trusted reverse proxy.
- UDP input is unauthenticated until packet armor is verified. Rate limiting,
  bounded fragment reassembly, bounded LZ4 expansion, and physical MTU limits
  constrain work performed before trust is established.
- The controller identity secret is created with mode `0600`; disclosure allows
  controller impersonation and loss changes the controller address.
- Upstream root identities and endpoints are trust configuration. Verify them
  independently and use only infrastructure you operate or are authorized to
  use.
- SQLite is a single-node persistence layer. Back up the database and identity
  together, and do not run multiple controller processes against the same
  files.

## Known first-release limits

- No private planet or moon implementation is included.
- Peer sessions are memory-resident. After a controller restart, agents must
  perform HELLO again before encrypted requests are accepted.
- The compatibility API implements the historical controller network/member
  contract documented in [LEGACY-CONTROLLER-API.md](LEGACY-CONTROLLER-API.md);
  unrelated local-node endpoints are not cloned.
- Clustering, SSO, a web UI, Redis, and PostgreSQL are out of scope.

The source and trademark constraints remain those documented in
[PROVENANCE.md](PROVENANCE.md). Passing these technical checks is not a
substitute for legal advice.
