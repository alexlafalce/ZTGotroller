# Initial roadmap

## Milestone 0: provenance baseline

- Preserve the upstream license audit.
- Document the permitted source boundary.
- Adopt Apache License 2.0 for original project work.
- Prevent accidental use of restricted controller sources.

## Milestone 1: protocol specification

Document:

- Network ID derivation and controller addressing.
- Network configuration requests and metadata.
- Legacy and signed-chunk configuration responses.
- Network configuration dictionary serialization.
- Certificates of Membership and signature verification.
- Rules, capabilities, tags, and revocations.

## Milestone 2: compatibility fixtures

Generate deterministic fixtures with the `1.14.2` reference implementation:

- Identities and signatures.
- Configuration requests and responses.
- Network configuration dictionaries.
- Certificates of Membership.
- Signed configuration chunks.

## Milestone 3: Go protocol primitives

Implement and validate:

- Identity parsing and compatible signatures.
- Network IDs.
- Dictionary encoding. (base fields, routes, managed addresses, and DNS complete)
- RFC4193 and 6PLANE derived IPv6 assignments with historical prefix semantics.
  (complete)
- Network configurations.
- Certificates of Membership. (issuance, serialization, and verification complete)
- Certificates of Ownership for assigned IPs. (issuance, serialization, and verification complete)
- Complete 1.14.2 rule type/length/value serialization, including actions,
  address/protocol/port matches, tags, characteristics, and integer ranges.
  (complete)
- Signed member capabilities and tags, including network defaults. (complete)
- Signed COM revocations with fast propagation to authenticated network peers
  when a member is deauthorized. (complete)
- Signed configuration chunks.
- Authorized configuration assembly with COM, COO, rules, dictionary, and signed chunks. (complete)
- Authenticated request handling, first-contact registration, authorization errors, and signed replies. (complete)
- C25519/Poly1305/Salsa20/12 packet construction, authentication, and encryption. (complete)
- HELLO identity bootstrap, proof validation, shared-key derivation, and encrypted OK response. (complete)
- Concurrent peer session registry with identity-collision and authenticated-packet handling. (complete)
- UDP datagram dispatcher for HELLO and NETWORK_CONFIG_REQUEST lifecycles. (complete)
- Runnable HTTP+UDP controller with coordinated shutdown and HELLO rate limiting. (complete)
- Administrative read/update API for routes, DNS, rules, authorization, and member IPs. (complete)
- Protocol-level outgoing fragmentation below physical MTU. (complete)
- Bounded, expiring inbound fragment reassembly before authentication. (complete)
- Protocol 12/13 AES-GMAC-SIV session armor with 48-byte key derivation. (complete)
- Configurable root HELLO announcements for controller identity discovery. (complete)
- Bounded inbound raw-LZ4 payload decompression. (complete)

## Milestone 4: minimal controller

Support:

- One persistent controller identity.
- Private networks.
- Explicit member authorization.
- Managed IPv4 assignment.
- Basic accept/drop rules.
- Durable SQLite storage.

The milestone is complete when a `1.14.2` agent and a current MPL agent obtain
configuration from ZTGotroller and establish peer-to-peer connectivity.

Status: complete. See [INTEROPERABILITY.md](INTEROPERABILITY.md).

## Milestone 5: sustainable self-hosting

- Provide a compatibility API for established self-hosted management clients,
  derived only from the Apache-2.0 baseline and black-box client tests.
  (controller network/member contract and peer telemetry complete)
- Validate at least one external management UI, such as
  [ZTNet](https://github.com/sinamics/ztnet), against that adapter. (current
  ZTNet client lifecycle complete; see
  [ZTNET-VALIDATION.md](ZTNET-VALIDATION.md))
- Allocate unique IPv4/IPv6 addresses from configured pools when the
  corresponding ZeroTier assignment mode is enabled. (complete)
- Publish reproducible binaries and container packaging. (complete)
- Define database and identity backup, restore, and schema migration workflows.
  (complete)
- Add health details and initial Prometheus metrics. (complete)
- Add JSON structured logs and upstream attempt/success status. (complete)
- Automate the mixed-version agent compatibility matrix. (repository runner
  and privileged lab-driver contract complete)
- Benchmark steady-state and loaded memory against the 1.14.2 executable using
  equivalent networks, members, requests, uptime, and platform constraints.
  (five-run equivalent state-load measurement complete; agent-driven load is a
  recurring release-lab measurement)

The project will not duplicate organization management, multi-user
administration, or web presentation already provided by external clients.

## Milestone 6: ongoing agent compatibility

- Test each supported MPL agent release without inspecting restricted
  controller sources or controller-specific changelogs.
- Derive changes from MPL agent code, public protocol documentation, and
  authorized black-box observations.
- Publish a compatibility matrix and regression fixtures for every supported
  agent line.

The executable matrix and evidence contract are documented in
[COMPATIBILITY-MATRIX.md](COMPATIBILITY-MATRIX.md). Each release still requires
a fresh run on the isolated privileged lab.

## Out of scope for the first release

- Private planets or moons.
- Controller clustering.
- Redis or PostgreSQL storage.
- SSO and multi-user administration.
- A built-in web interface or organization-management layer.
- Full compatibility with unrelated local-node service endpoints.
