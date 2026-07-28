# Controller schema

This document describes schema version 1 of the controller's persistent domain
model. It is a clean Go model informed by the Apache-2.0 ZeroTier One 1.14.2
controller behavior documented in `docs/PROVENANCE.md`.

## Boundaries

Persistent desired configuration is separated from replaceable runtime
observations:

- `Network` stores network policy, assignment modes, routes, address pools, DNS,
  capabilities and tag definitions.
- `Member` stores authorization and other administrator-owned member settings.
- `MemberStatus` stores online state, last-seen time and agent/protocol versions.
- `Store` defines persistence without selecting a database implementation.

Wire packet encoding, signing, identity management, root/planet/moon management,
SSO and the HTTP API are outside schema version 1. They will be implemented as
adapters and services over this model.

The application service in `internal/controller` currently owns the first
controller workflows: creating a network, idempotently registering a member as
unauthorized, and explicitly changing member authorization with an expected
revision. It also rejects network IDs owned by another controller identity.

## Compatibility notes

The defaults intentionally reproduce the 1.14.2 controller:

- networks are private;
- MTU is 2800, constrained to 1280–10000;
- multicast limit is 32;
- broadcast is enabled;
- automatic address assignment modes are initially disabled;
- the default rule is `ACTION_ACCEPT`.

Network IDs contain the 40-bit controller node ID followed by a 24-bit sequence.
Node IDs and network IDs use canonical lowercase hexadecimal.

Rules preserve their historical type plus JSON parameters. The protocol
adapter validates and serializes the complete rule catalog supported by the
1.14.2 baseline. Unknown future rule types remain rejected instead of being
silently converted to empty fields.

Capabilities reference their rules by definition and are issued only to
members that list the capability, plus definitions marked as default. Tags use
member values when present and numeric network defaults otherwise. Both are
signed for the recipient and included as `CAP` and `TAG` credentials in the
network configuration.

When `ipv4ZeroTier` or `ipv6ZeroTier` is enabled, an authorized member without
an address in that family receives the first free address from the configured
pools. Allocation is serialized, ignores addresses outside managed routes, and
respects `noAutoAssignIps` and explicit assignments.

Every persisted aggregate carries a schema version and revision. Store
implementations must use the revision for optimistic concurrency.

## In-memory reference store

`internal/store/memory` is the first implementation of the persistence
contract. It is intended for service tests and local development, not durable
operation. It provides:

- deterministic list ordering;
- isolated copies on reads and writes;
- revision checks for updates and deletes;
- thread-safe access;
- cascading member deletion when a network is deleted.

Creation persists revision 1. An update must provide the current revision and
persists the next revision. A client should read the aggregate again after an
update when it needs the authoritative revision.

## SQLite store

`internal/store/sqlite` provides durable embedded persistence. Schema migration
1 stores versioned network and member documents with indexed identity and
revision columns. Foreign keys enforce member ownership and cascade member
deletion with their network. WAL mode and a busy timeout are enabled at open.

The driver is a CGo-free SQLite implementation so builds retain straightforward
cross-compilation across its supported operating systems and architectures.
