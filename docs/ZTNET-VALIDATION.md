# ZTNet compatibility validation

ZTGotroller was validated on July 28, 2026 against the unmodified ZTNet client
module from public commit
`3ba175a682d03edd72516d830667ee08fe3cf262`.

The test imports ZTNet's real `src/utils/ztApi.ts`. Only its Prisma lookup is
mocked so the client receives the test controller URL and token; network and
member operations still travel through ZTNet's Axios code over HTTP to a real
ZTGotroller process.

The passing lifecycle covers:

- node status and controller status;
- network creation using the historical random-ID endpoint;
- network list, read, update, and delete;
- member create/update, list, detail, authorization, and delete; and
- peer telemetry list.

Run the pinned validation with:

```sh
./scripts/ztnet-contract-test.sh
```

It clones the exact public ZTNet commit into a temporary directory, installs
its locked dependencies, injects the repository-owned integration test, builds
ZTGotroller, and runs the external client's Jest test. Nothing is written into
the ZTGotroller working tree. `ZTNET_REF` may be overridden deliberately when
qualifying a later ZTNet revision; update this document and the default pin
only after the new revision passes.

This validates the management-client/controller contract, not ZTNet's browser
rendering, authentication pages, PostgreSQL persistence, or organization
features. Those layers do not change the HTTP payload exercised here.
