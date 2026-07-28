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

The Go signing implementation was checked byte-for-byte against
`C25519::sign` compiled from 1.14.2 using the known identity in
`selftest.cpp` and the message
`ZTGotroller cross-language signature vector`. Both implementations produced:

```text
ae40a9650a9a41cbad407e9b6fe2c0f63bcbde09fdff53bfff7a852e41479fe0
150057872ae58da6abe7abc27df723c814bbf4c5ebd87b5e56e32daa1f856c079b
c20ce84c12a0d91d0f77c8d069eba5cfdbcf3aefd594f267e3d98576aef5ff
```

The first 64 bytes are a standard Ed25519 signature over the first 32 bytes of
`SHA-512(message)`; the final 32 bytes repeat that digest prefix. Verification
checks both parts.

Local validation implements the same memory-hard composition and accepts the
known-good 1.14.2 self-test identity while rejecting its known altered-address
variant and an altered public key. Validation allocates a 2 MiB work area per
call, as the original algorithm requires.

Curve25519 agreement was checked against `C25519::agree` from 1.14.2. Using the
known self-test identity for both sides and requesting 64 bytes produced:

```text
5e912d05aab6562b1252f6e93f9ef85dd03c5fdf5cf0c0d0014bb21781a1cb08
0497c73264833e319f0484b569668d20f0bcfe56d2e5df58a5a6f13b56d56eeb
```

Both implementations perform X25519 with the first 32-byte key pair, hash the
raw secret with SHA-512 and repeatedly hash the previous digest when more than
64 output bytes are requested.

Identity generation holds the Ed25519 half fixed while iterating the X25519
private half until the public key satisfies the address proof of work, matching
the type-0 generation strategy. Generation accepts a context so callers can
cancel the intentionally expensive search and accepts an injectable random
reader for deterministic compatibility tests.

With 64 zero bytes as the injected random source, generation finds the
address `a7fa8660c2` after seven X25519 candidates. The resulting public
identity was serialized into the 1.14.2 binary format and accepted by
`Identity::locallyValidate()` compiled from the 1.14.2 C++ sources.

The server loads or creates `identity.secret` and derives the controller ID
from it. Installation uses a same-directory temporary file, `fsync`, mode
`0600` and an atomic hard link that cannot replace an identity created by
another process. Loading rejects symlinks, public-only files, unsafe
permissions and invalid proof of work.
