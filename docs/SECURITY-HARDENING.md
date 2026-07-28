# Memory-exhaustion hardening

ZTGotroller applies fixed or explicitly bounded memory policies to every
unauthenticated UDP admission path:

- HELLO rate limiting uses 16,384 fixed buckets. IPv4 `/24` and IPv6 `/48`
  prefixes share buckets, so arbitrary source addresses cannot grow a map.
- Fragment reassembly permits 32 simultaneous partial packets, retains at most
  one complete protocol packet worth of bytes per slot, ignores duplicate
  fragments, and expires incomplete sets after five seconds.
- Authenticated learned-peer sessions are capped at 16,384 and expire after ten
  minutes without traffic. Configured upstream sessions are not evicted.
- A successful HELLO performs the 2 MiB memory-hard identity proof once; the
  registry trusts the result already established by the authenticated parser.

The public `/healthz` endpoint performs only a persistence ping and does not
enumerate or clone controller state. Detailed counts remain behind
authentication at `/metrics`.

Administrative JSON bodies are limited to 1 MiB on the native API and 8 MiB on
the historical compatibility API. Both accept exactly one JSON value.

These controls target availability and heap exhaustion. They complement packet
authentication and do not replace host firewalling: expose UDP only where
required, keep the HTTP API on loopback or a protected management network, and
apply process or container memory limits as a final containment boundary.
