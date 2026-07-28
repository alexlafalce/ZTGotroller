# ZeroTier identity compatibility

## Reviewed sources

The identity format and constants were checked independently against:

- ZeroTier One 1.14.2 commit
  `185a3a2c76e6bf1b1c0415871f43076638eb007c`, specifically the Apache-2.0
  `node/Identity.*`, `node/C25519.*`, `node/Address.hpp` and
  `selftest.cpp`.
- The MPL-2.0 agent `dev` snapshot
  `899352e38405968516bb12a770f0ac02f6058fa8`, specifically
  `node/Identity.*` and `node/ECC.*`.

The contemporary non-FIPS implementation retains identity type 0 and the same
normal key framing. The current code calls the primitive set `ECC` rather than
`C25519`. FIPS identities use different key sizes and are intentionally outside
the first compatibility target.

## Type 0 format

The text form is:

```text
<10 hex address>:0:<128 hex public key>[:<128 hex private key>]
```

The 64-byte public and private key sets each contain a 32-byte Curve25519 key
and a 32-byte Ed25519 key. A ZeroTier signature is 96 bytes: a 64-byte Ed25519
signature followed by 32 bytes from `SHA-512(message)`.

The binary public form is 71 bytes:

```text
5-byte address | 1-byte type | 64-byte public key | 1-byte private length (0)
```

The binary secret form is 135 bytes and sets the private length byte to 64,
followed by the 64 private bytes.

## Address derivation

An address is derived from the final five bytes of a memory-hard hash of the
public key. The algorithm uses SHA-512, Salsa20, a 2 MiB work area and requires
the first digest byte to be less than 17. All-zero addresses and addresses
beginning with `ff` are reserved.

Schema support in this milestone parses and serializes identities. It does not
yet claim local proof-of-work validation, identity generation, ECDH agreement
or 96-byte signing. Those operations require cross-language vectors before
being exposed to controller services.
