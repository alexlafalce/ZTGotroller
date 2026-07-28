# ZeroTier packet framing

The common UDP packet header remains 28 bytes in both protocol 12 (ZeroTier
One 1.14.2) and protocol 13 (the reviewed MPL `dev` snapshot):

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | IV / packet ID, big endian |
| 8 | 5 | destination ZeroTier address |
| 13 | 5 | source ZeroTier address |
| 18 | 1 | flags, cipher and hop count |
| 19 | 8 | MAC / authenticator |
| 27 | 1 | verb and compression flag |
| 28 | variable | payload |

The flags byte is `FFCCCHHH`: bit 7 is extended armor in protocol 13, bit 6
means fragmented, bits 3–5 select the cipher and bits 0–2 contain the hop
count. Protocol 12 treated bit 7 as deprecated.

Protocol 13 is not merely a new verb. It uses extended armor with ephemeral
keying and a second encryption pass, including encrypted HELLO packets for
non-root destinations. Therefore the routing parser exposes only packet ID,
addresses and flags before authentication. Verb and payload parsing is a
separate operation that callers may use only after decryption and
authentication.

Subsequent fragments use a 16-byte header: packet ID, destination, the reserved
`ff` indicator, a nibble pair containing total/number, one hop byte and the
fragment payload. Fragments have no individual MAC and must not be trusted
until the complete packet is reassembled and authenticated.

Reviewed sources:

- Apache-2.0 ZeroTier One 1.14.2 `node/Packet.hpp`.
- MPL-2.0 agent snapshot `899352e38405968516bb12a770f0ac02f6058fa8`
  `node/Packet.hpp`.
