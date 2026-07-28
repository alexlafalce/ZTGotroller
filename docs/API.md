# Administrative API

The first HTTP adapter exposes a deliberately small, controller-native API:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/networks` | Create a network from a 24-bit sequence and name |
| `GET` | `/v1/networks` | List networks |
| `GET` | `/v1/networks/{networkID}` | Read one network |
| `PUT` | `/v1/networks/{networkID}` | Replace configurable network fields using an expected revision |
| `GET` | `/v1/networks/{networkID}/members` | List members |
| `GET` | `/v1/networks/{networkID}/members/{nodeID}` | Read one member |
| `POST` | `/v1/networks/{networkID}/members/{nodeID}` | Idempotently register an unauthorized member |
| `PUT` | `/v1/networks/{networkID}/members/{nodeID}` | Replace member IPs and other configurable fields using an expected revision |
| `PUT` | `/v1/networks/{networkID}/members/{nodeID}/authorization` | Change authorization using an expected revision |

Request bodies are limited to 1 MiB, reject unknown fields and accept exactly
one JSON value. Domain conflicts return HTTP 409 and missing resources return
HTTP 404.

Managed IP assignments must be contained by at least one route of the same
address family. The most-specific containing route supplies the prefix sent to
the agent. Updates use full replacement semantics for their configurable
fields and require the current `revision`.

This is an administrative API, not the ZeroTier agent wire protocol and not yet
a compatibility implementation of the historical controller HTTP API. Those
interfaces will be separate adapters over the same application service.
