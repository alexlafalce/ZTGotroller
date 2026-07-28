# Contributing to ZTGotroller

By contributing, you agree to follow the
[clean-room policy](docs/CLEAN-ROOM-POLICY.md) and the source boundaries in
[PROVENANCE.md](docs/PROVENANCE.md).

## Before implementing compatibility changes

Open an issue or record in the pull request:

1. The affected agent and UI/client versions.
2. The permitted evidence supporting the expected behavior.
3. A black-box or independently authored test that demonstrates the gap.
4. Whether any MPL-covered expression will be copied.

Do not inspect restricted controller code to answer an implementation question.
If the permitted evidence is insufficient, document the unknown and design a
black-box experiment.

## Pull request declaration

Every pull request must confirm that:

- no prohibited source was consulted, copied, translated, or adapted;
- controller-specific restricted changelogs were not used as an implementation
  specification;
- copied third-party or MPL expression is identified with its license;
- new dependencies and generated artifacts received a license review; and
- compatibility claims have a reproducible test or fixture.

If you cannot truthfully make these declarations, stop and describe the
possible contamination privately to the maintainers. Do not submit the
affected implementation.

## Engineering checks

Run:

```sh
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
```

Protocol changes should also be tested against an unmodified supported agent.
Do not include private identities, production packet captures, API tokens, or
third-party confidential data in fixtures.
