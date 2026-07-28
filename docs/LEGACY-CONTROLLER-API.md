# ZeroTier 1.14.2 controller API compatibility

ZTGotroller provides a compatibility adapter for the local controller HTTP API
implemented by the Apache-2.0 `1.14.2` baseline. The adapter is independent of
the controller-native `/v1` API and uses the same application service and
SQLite state.

## Authentication

The configured `ZTGOTROLLER_API_TOKEN` is accepted through either:

- `X-ZT1-Auth: <token>`, used by the historical local service API; or
- `Authorization: Bearer <token>`, used by the controller-native API.

`/healthz` remains unauthenticated.

## Contract matrix

| Method | Path | Result |
| --- | --- | --- |
| `GET` | `/status` | Local-node identity and service status required by management clients |
| `GET` | `/controller` | Controller API and database readiness |
| `GET` | `/controller/network` | Array of network IDs |
| `POST`, `PUT` | `/controller/network` | Create a network with a random owned ID |
| `POST`, `PUT` | `/controller/network/{controller}______` | Historical random-ID creation form |
| `GET` | `/controller/network/{nwid}` | Network configuration |
| `POST`, `PUT` | `/controller/network/{nwid}` | Partial network update |
| `DELETE` | `/controller/network/{nwid}` | Delete and return a network |
| `GET` | `/controller/network/{nwid}/member` | Object mapping member IDs to revisions |
| `GET` | `/controller/network/{nwid}/member/{node}` | Member configuration |
| `POST`, `PUT` | `/controller/network/{nwid}/member/{node}` | Register or partially update a member |
| `DELETE` | `/controller/network/{nwid}/member/{node}` | Delete and return a member |
| `GET` | `/unstable/controller/network` | Networks with aggregate member metadata |
| `GET` | `/unstable/controller/network/{nwid}/member` | Members with aggregate authorization metadata |

The adapter accepts unknown JSON properties, applies partial-update semantics,
and renders legacy names such as `nwid`, `v4AssignMode`,
`ipAssignmentPools`, `creationTime`, and member tag pairs. Invalid routes and
IP pools are discarded in the same spirit as the reference controller.

## Compatibility boundary

This contract covers controller network and member administration. General
ZeroTier node endpoints such as `/peer` describe the local node transport,
rather than controller configuration, and will be backed by the Go runtime
telemetry work.

The source of truth for effective network state is ZTGotroller. Management
clients send JSON over this API; ZTGotroller persists the normalized model and
generates signed network configurations. No process reload is required after a
network or member update.
