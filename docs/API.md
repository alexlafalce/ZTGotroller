# Administrative API

The first HTTP adapter exposes a deliberately small, controller-native API:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/networks` | Create a network from a 24-bit sequence and name |
| `POST` | `/v1/networks/{networkID}/members/{nodeID}` | Idempotently register an unauthorized member |
| `PUT` | `/v1/networks/{networkID}/members/{nodeID}/authorization` | Change authorization using an expected revision |

Request bodies are limited to 1 MiB, reject unknown fields and accept exactly
one JSON value. Domain conflicts return HTTP 409 and missing resources return
HTTP 404.

This is an administrative API, not the ZeroTier agent wire protocol and not yet
a compatibility implementation of the historical controller HTTP API. Those
interfaces will be separate adapters over the same application service.
