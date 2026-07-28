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
- Network configurations.
- Certificates of Membership. (issuance, serialization, and verification complete)
- Certificates of Ownership for assigned IPs. (issuance, serialization, and verification complete)
- Basic accept/drop rules. (complete)
- Signed configuration chunks.
- Authorized configuration assembly with COM, COO, rules, dictionary, and signed chunks. (complete)
- Authenticated request handling, first-contact registration, authorization errors, and signed replies. (complete)

## Milestone 4: minimal controller

Support:

- One persistent controller identity.
- Private networks.
- Explicit member authorization.
- Managed IPv4 assignment.
- Basic accept/drop rules.
- JSON file storage.

The milestone is complete when a `1.14.2` agent and a current MPL agent obtain
configuration from ZTGotroller and establish peer-to-peer connectivity.

## Out of scope for the first release

- Private planets or moons.
- Controller clustering.
- Redis or PostgreSQL storage.
- SSO and multi-user administration.
- A web interface.
- Full compatibility with the historical controller API.
