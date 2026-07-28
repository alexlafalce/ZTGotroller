# Network configuration request

After packet reassembly, authentication, decryption and decompression, a
`NETWORK_CONFIG_REQUEST` payload contains:

| Size | Field |
| ---: | --- |
| 8 | network ID, big endian |
| 2 | metadata dictionary length, big endian |
| variable | escaped metadata dictionary |
| 8 | current configuration revision |
| 8 | current configuration timestamp |
| variable | future extension bytes |

The final 16-byte state trailer is absent in sufficiently old requests and is
therefore optional as a whole. A partial trailer is invalid. Current 1.14.2 and
MPL agents emit it, using sixteen zero bytes when no configuration exists.

Metadata is a newline-separated `key=value` dictionary. Values escape null,
carriage return, newline, equals and backslash as `\0`, `\r`, `\n`, `\e` and
`\\`. Numeric metadata values are hexadecimal without a prefix. Duplicate keys
retain the first value, matching `Dictionary::get`.

The decoder caps metadata at 1023 bytes, rejects raw nulls and malformed keys,
and preserves unknown extension bytes. Compressed payloads are rejected until
the transport layer has decompressed them.

Reviewed sources:

- Apache-2.0 ZeroTier One 1.14.2 `node/Dictionary.hpp`,
  `node/Network.cpp`, `node/IncomingPacket.cpp` and `node/NetworkConfig.hpp`.
- MPL-2.0 agent snapshot `899352e38405968516bb12a770f0ac02f6058fa8`
  equivalents.
