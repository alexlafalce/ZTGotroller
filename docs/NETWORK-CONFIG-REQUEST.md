# Network configuration request

After packet reassembly, authentication, decryption and bounded raw-LZ4
decompression, a
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
and preserves unknown extension bytes. The transport layer decompresses
authenticated payloads before this parser is called.

Reviewed sources:

- Apache-2.0 ZeroTier One 1.14.2 `node/Dictionary.hpp`,
  `node/Network.cpp`, `node/IncomingPacket.cpp` and `node/NetworkConfig.hpp`.
- MPL-2.0 agent snapshot `899352e38405968516bb12a770f0ac02f6058fa8`
  equivalents.

## Signed response chunks

The response body after the `OK` correlation fields is divided into signed
chunks:

```text
network ID | uint16 data length | data | flags |
update ID | uint32 total length | uint32 index |
signature type | uint16 signature length | signature
```

Network ID through chunk index are signed using the controller identity. Type
1 carries the 96-byte ZeroTier Ed25519 signature. The `OK` wrapper contains the
original verb (`NETWORK_CONFIG_REQUEST`) and request packet ID but is outside
the chunk signature. Transport authentication protects that wrapper.

Update IDs must be non-zero. Chunk ranges cannot exceed the declared assembled
length, and an assembled dictionary is limited to less than 1 MiB in this
implementation. Dictionary content generation is the next layer and is
deliberately separate from signed framing.
