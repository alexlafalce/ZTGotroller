# ZTGotroller

Community controller research and implementation for ZeroTier-compatible
self-hosting.

> [!WARNING]
> **Beta software.** ZTGotroller is under active development and has not been
> validated for production, safety-critical, high-availability, or other
> environments where failure could cause material harm. It may contain defects,
> security vulnerabilities, incomplete behavior, incompatibilities, and
> breaking changes, and its use may cause loss of data, loss of connectivity,
> service interruption, or unintended network exposure. Evaluate it in an
> isolated environment and maintain tested backups and a recovery path.

## Disclaimer and limitation of liability

Use of this software is entirely at your own risk. To the maximum extent
permitted by applicable law, the software is provided **"AS IS"** and **"AS
AVAILABLE," WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND**, whether express,
implied, statutory, or otherwise. This includes, without limitation, warranties
of title, non-infringement, merchantability, fitness for a particular purpose,
accuracy, availability, compatibility, security, reliability, and freedom from
defects. No representation or guarantee is made that the software will meet
your requirements, remain compatible with any current or future ZeroTier
agent, protocol, API, operating system, or third-party integration, or receive
maintenance, support, security updates, or vulnerability remediation.

To the maximum extent permitted by applicable law, the authors, copyright
holders, contributors, maintainers, and distributors will not be liable for
any direct, indirect, incidental, special, exemplary, punitive, or
consequential damages, or for any loss of data, credentials, traffic, profits,
revenue, business, goodwill, or use; network or service interruption;
unauthorized access or disclosure; security breach; corruption or damage to
systems or devices; recovery costs; or third-party claims arising from or
related to the software or its use or inability to be used, regardless of the
theory of liability and even if advised of the possibility of such damages.

Operating a network controller can grant access to private systems and route
traffic between devices. You are solely responsible for deployment decisions,
authorization policies, firewalling and segmentation, transport security,
credential and key protection, updates, monitoring, capacity planning,
backups, disaster recovery, incident response, regulatory compliance, and
obtaining all permissions required for the networks, systems, data, and
third-party services involved. This software is not a substitute for endpoint,
network, or operational security controls.

Third-party agents, user interfaces, libraries, services, protocols, and
trademarks remain subject to their own licenses, terms, and policies. Their
interoperability with this project does not imply affiliation, endorsement, or
support. You are responsible for determining whether your intended use and
distribution comply with all applicable licenses, contracts, export controls,
privacy requirements, and laws.

This notice supplements the warranty disclaimer and limitation of liability in
the [Apache License 2.0](LICENSE). If this notice conflicts with that license,
the license controls. Nothing here excludes or limits liability that cannot
lawfully be excluded or limited. This notice is general information, not legal
advice; consult qualified counsel for advice about your circumstances.

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

The historical API also accepts `X-ZT1-Auth`. Container deployment,
health/metrics, backup, restore, migrations, and reproducible release details
are documented in [OPERATIONS.md](docs/OPERATIONS.md).

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

Compatibility support for the ZeroTier One 1.16.2 agent is currently beta. It
includes encrypted HELLO extended armor, 512 network specialists, experimental
network-relay roles, and persisted agent platform/capability metadata. See
[AGENT-1.16.2-BETA.md](docs/AGENT-1.16.2-BETA.md) for its scope and limitations.

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
