# ZTGotroller

ZTGotroller is an independent, community-oriented network controller intended
to interoperate with MPL-licensed ZeroTier agents while preserving the option
to self-host network management.

The controller implementation will be derived only from the ZeroTier One
`1.14.2` source snapshot, whose Business Source License declares a change to
Apache License 2.0 effective on January 1, 2026. Compatibility with newer
agents will be developed from the MPL-licensed agent code, public protocol
documentation, and interoperability tests.

## Status

The project is in its provenance and protocol-analysis phase. No functional
controller has been implemented yet.

The first interoperability milestone is:

1. Run one ZeroTier One `1.14.2` agent and one current MPL agent.
2. Join both agents to a private network managed by ZTGotroller.
3. Authorize both members and assign IPv4 addresses.
4. Establish peer-to-peer connectivity between them.

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
[the license audit](audit/LICENSE-AUDIT-1.14.2.md) for the baseline findings.

## License

Unless a file states otherwise, original work in this repository is licensed
under Apache License 2.0. See [LICENSE](LICENSE).

This project is independent and is not affiliated with, endorsed by, or
sponsored by ZeroTier, Inc. ZeroTier is a trademark of ZeroTier, Inc.
