# Upstream discovery

An unmodified agent must learn the controller's public identity before it can
authenticate packets addressed to the controller. A static physical path hint
alone does not distribute that identity.

ZTGotroller can periodically send authenticated ZeroTier HELLO packets to
configured upstream roots. A root that accepts the announcement can then
answer agent WHOIS requests for the controller. This is ordinary peer
bootstrap; ZTGotroller does not become a planet or moon and does not embed a
copy of ZeroTier's public infrastructure configuration.

Create a JSON file containing public identities and reachable UDP endpoints:

```json
{
  "upstreams": [
    {
      "identity": "<node-id>:0:<128-hex-character-public-key>",
      "endpoints": ["192.0.2.10:9993", "[2001:db8::10]:9993"]
    }
  ]
}
```

Start the controller with `-upstreams ./upstreams.json`. The file is validated
at startup. Private identities are rejected. Announcements are sent
immediately and every 30 seconds; replies must be authenticated, originate
from the configured identity and endpoint, and match the request packet ID and
timestamp.

Root identities and endpoints are operational trust configuration. Obtain them
from infrastructure you operate or are authorized to use, verify them through
a trusted channel, and update them when that infrastructure changes. Merely
listing a third-party root does not guarantee that it will retain or publish
the controller identity.

For direct path hints, agents support a `local.conf` entry shaped like:

```json
{
  "virtual": {
    "<controller-node-id>": {
      "try": ["203.0.113.20/9993"]
    }
  }
}
```

The path hint tells the agent where to send packets; it does not replace
identity discovery. Use both when the controller is not otherwise reachable
through normal ZeroTier path discovery.
