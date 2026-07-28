# ZeroTier One 1.16.2 agent compatibility beta

ZTGotroller implements the following compatibility changes derived exclusively
from the MPL-2.0 agent source, public release notes, and interoperability tests:

- protocol-13 encrypted HELLO packets using extended armor;
- up to 512 network specialists;
- active bridge, multicast replicator, and network relay specialist roles; and
- persisted agent platform, architecture, version, protocol, rules-engine, and
  advertised capacity metadata.

The `networkRelay` role is experimental. ZeroTier One 1.16.2 recognizes the
specialist flag and maintains the designated node as an always-contact peer,
but network-specific relay selection remains a preview feature in the public
agent. Do not treat this role as a replacement for roots or as a
high-availability guarantee.

## Member API fields

The legacy-compatible member API accepts these role fields:

```json
{
  "activeBridge": false,
  "multicastReplicator": false,
  "networkRelay": false
}
```

Only authorized members are emitted as specialists. A role or authorization
change advances the network configuration revision so connected agents can
obtain a replacement configuration.

## Encrypted HELLO

Agents may enable encrypted HELLO packets in `local.conf`:

```json
{
  "settings": {
    "encryptedHelloEnabled": true
  }
}
```

ZTGotroller decrypts the ephemeral X25519/AES-CTR layer before authenticating
the ordinary HELLO session armor. HELLO processing remains subject to the
per-source rate limiter, packet-size checks, identity proof validation, and
message authentication.

## Database migration

Opening an existing schema-version-1 database automatically creates the
`agent_metadata` table and advances `PRAGMA user_version` to 2. Back up both
`ztgotroller.db` and `identity.secret` before upgrading. Older binaries refuse
to open the migrated database because its schema is newer.

## Validation scope

Automated tests cover:

- extended-armor HELLO authentication and tamper rejection;
- the complete UDP handler path for encrypted HELLO;
- combined specialist role encoding;
- the 512-entry boundary and 513-entry rejection;
- metadata projection and durable SQLite storage; and
- migration from database schema version 1.

Real-agent interoperability with the official 1.16.2 binary remains required
before removing the beta designation.

## Provenance record

- Observable problem: an agent with encrypted HELLO enabled cannot bootstrap
  to the controller; specialist roles and agent inventory metadata are not
  represented completely.
- Affected agent: ZeroTier One `1.16.2`, tag commit
  `fc5c3ec22090b5b2a0f274e863651fe9ca489bf4`.
- Permitted sources: the MPL-2.0 files `include/ZeroTierOne.h`,
  `node/Constants.hpp`, `node/Network.cpp`, `node/NetworkConfig.cpp`,
  `node/NetworkConfig.hpp`, `node/Packet.cpp`, `node/Packet.hpp`,
  `node/Peer.cpp`, `node/Topology.cpp`, and `service/OneService.cpp`; the
  public agent release notes; and the independently authored Go tests listed
  above.
- Controller baseline reference: the Apache-2.0 `1.14.2` tag was consulted
  only to confirm the historical active-bridge configuration behavior.
- Copied expression: none. Constants and wire identifiers required for
  interoperability are re-expressed in independently authored Go code.
- Clean-room declaration: no `nonfree/` file, post-1.14.2 commercially
  licensed controller source, private repository, or restricted
  controller-specific implementation material was used.
