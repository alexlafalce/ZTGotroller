# Operations

## Container

Set a long random API token and start the controller:

```sh
export ZTGOTROLLER_API_TOKEN="$(openssl rand -hex 32)"
docker compose up -d --build
```

UDP port 9993 must be reachable by agents. HTTP port 9994 is bound to loopback
by the supplied Compose file and should only be published through an
authenticated TLS reverse proxy.

The image runs without root, drops Linux capabilities, has a read-only root
filesystem, and keeps the database and controller identity in the named
`ztgotroller-data` volume.

## Health and metrics

`GET /healthz` is public and verifies that persistence can list every network
and its members. It reports controller address plus network, member, and
authenticated-peer counts. When upstream discovery is configured it also
reports each root endpoint's last attempt, last successful authenticated
HELLO, and whether an announcement is pending.

`GET /metrics` uses the Prometheus text format and requires the configured API
token. Initial gauges cover persistence availability and aggregate network,
member, and peer counts.

Application logs are one-line JSON records suitable for journald, Loki, or
another structured-log collector. Secret identities, API tokens, session keys,
and packet bodies are never included.

## Backup

The backup command creates a new mode-0700 directory containing a consistent
SQLite snapshot and a mode-0600 copy of the controller identity:

```sh
ztgotroller-backup \
  -database /var/lib/ztgotroller/ztgotroller.db \
  -identity /var/lib/ztgotroller/identity.secret \
  -output /backups/ztgotroller-2026-07-28
```

The destination must not already exist. Store it encrypted: disclosure of
`identity.secret` permits impersonating the controller.

For the Compose deployment:

```sh
docker compose run --rm --entrypoint /usr/local/bin/ztgotroller-backup \
  -v "$PWD/backups:/backups" controller \
  -database /var/lib/ztgotroller/ztgotroller.db \
  -identity /var/lib/ztgotroller/identity.secret \
  -output /backups/ztgotroller-2026-07-28
```

## Restore

Stop the controller, place both backup files in an empty data directory, retain
mode 0600 on `identity.secret`, and restart. Never restore the database without
its matching identity: network IDs embed the controller address.

Always retain the pre-upgrade backup until agents have joined successfully and
the administrative API has been verified.

## Schema migrations

SQLite `PRAGMA user_version` identifies the schema. Migrations run
transactionally during startup. A binary refuses databases with a newer schema
version, preventing accidental downgrade. Backup before installing a release
that changes the schema.

## Reproducible releases

Tag pushes matching `v*` build trimmed, static binaries for Linux, macOS, and
Windows, publish SHA-256 sums, and build the container in CI. Builds clear the
Go build ID and remove local filesystem paths with `-trimpath`.
