# ZTGotroller

Community controller research and implementation for ZeroTier-compatible
self-hosting.

## Run the controller

```sh
export ZTGOTROLLER_API_TOKEN='replace-with-a-long-random-token'
go run ./cmd/ztgotroller \
  -identity ./identity.secret \
  -database ./ztgotroller.db \
  -listen 127.0.0.1:9994 \
  -udp-listen :9993 \
  -upstreams ./upstreams.json
```

The administrative API listens on `127.0.0.1:9994` and the ZeroTier protocol
listener uses UDP `9993` by default. The UDP port must be reachable by agents.
The optional upstream file lets the controller announce its identity to known
roots so agents can discover it through WHOIS. See
[UPSTREAM-DISCOVERY.md](docs/UPSTREAM-DISCOVERY.md). It is not needed when
another trusted bootstrap mechanism already distributes the controller's
public identity.
All administrative routes require `Authorization: Bearer <token>`;
`/healthz` is intentionally public. Binding the HTTP API to a non-loopback
address should only be done behind TLS or a trusted reverse proxy.

On first start, the service generates `identity.secret` with mode `0600`.
Subsequent starts validate and reuse it. Back up this file securely: losing it
changes the controller address, while disclosure compromises the controller
identity. The service refuses symlinks, public-only identities and secret files
readable by group or other users.

ZTGotroller is an independent, community-oriented network controller intended
to interoperate with MPL-licensed ZeroTier agents while preserving the option
to self-host network management.

The project focuses on the controller and its sustainable compatibility
surface. It does not aim to build another web interface. Existing self-hosted
management projects can integrate through a compatibility API as that adapter
is completed.

The controller implementation will be derived only from the ZeroTier One
`1.14.2` source snapshot, whose Business Source License declares a change to
Apache License 2.0 effective on January 1, 2026. Compatibility with newer
agents will be developed from the MPL-licensed agent code, public protocol
documentation, and interoperability tests.

## Status

The project has a tested domain model, durable SQLite persistence, an
authenticated administrative API, ZeroTier-compatible identity and packet
cryptography, bidirectional HELLO/session handling, root announcements, and
signed private-network configuration responses. Interoperability is validated
between an unmodified `1.14.2` agent and the current MPL `origin/dev` agent,
including peer-to-peer connectivity.

The first interoperability milestone is complete:

1. Run one ZeroTier One `1.14.2` agent and one current MPL agent.
2. Join both agents to a private network managed by ZTGotroller.
3. Authorize both members and assign IPv4 addresses.
4. Establish peer-to-peer connectivity between them.

See [INTEROPERABILITY.md](docs/INTEROPERABILITY.md) for validated runs and
their exact scope.

## Repository policy

- The only controller source baseline is ZeroTier One `1.14.2`, commit
  `185a3a2c76e6bf1b1c0415871f43076638eb007c`.
- Code from `nonfree/`, ZeroTier One `1.16.x`, or later restricted controller
  implementations must not be copied into this repository.
- New protocol compatibility must be supported by MPL agent code, public
  documentation, observable behavior, or independently authored tests.
- Third-party dependencies must receive an individual license review.
- ZeroTier trademarks and logos are not licensed by Apache License 2.0.

See [PROVENANCE.md](docs/PROVENANCE.md) for the complete source policy and
[the clean-room policy](docs/CLEAN-ROOM-POLICY.md) before contributing.
The [license audit](audit/LICENSE-AUDIT-1.14.2.md) records the baseline
findings.

## License

Unless a file states otherwise, original work in this repository is licensed
under Apache License 2.0. See [LICENSE](LICENSE).

This project is independent and is not affiliated with, endorsed by, or
sponsored by ZeroTier, Inc. ZeroTier is a trademark of ZeroTier, Inc.
