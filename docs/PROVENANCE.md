# Source provenance policy

## Permitted controller baseline

The sole controller implementation used as a source reference is:

- Project: ZeroTier One
- Tag: `1.14.2`
- Commit: `185a3a2c76e6bf1b1c0415871f43076638eb007c`
- Upstream repository: `https://github.com/zerotier/ZeroTierOne`
- Upstream controller path: `controller/`
- Declared BSL Change Date: `2026-01-01`
- Declared Change License: Apache License 2.0

Each of the 15 tracked files in that controller directory contains an
individual notice stating that use will be governed by Apache License 2.0 on
the Change Date.

The upstream root license identifies the Licensed Work as version `1.4.4`
despite being distributed in tag `1.14.2`. This mismatch is recorded as a
residual legal ambiguity and must not be concealed or silently reinterpreted.

## Permitted compatibility sources

Compatibility work for later agents may use:

- Code expressly covered by the agent's Mozilla Public License 2.0.
- Public ZeroTier protocol and product documentation.
- Network traces captured from systems the contributor is authorized to test.
- Independently authored interoperability tests and fixtures.
- Public issue reports and agent release notes describing externally observable
  behavior.

If expression from an MPL-covered file is copied into this repository, the
resulting covered file must be identified and handled under MPL 2.0. Prefer
documenting behavior and implementing it independently in Go.

## Prohibited sources

Do not copy, translate, or adapt:

- `nonfree/` from ZeroTier One `1.16.x` or later.
- Any source-available or commercially licensed controller implementation
  released after the permitted baseline.
- Private ZeroTier repositories or confidential documentation.
- Material obtained under an agreement that prohibits this use.
- Decompilations of proprietary binaries.
- Controller-specific changelogs or release notes used as implementation
  specifications.
- Requirements or summaries that reproduce restricted implementation details.

## Contribution records

Compatibility changes should record:

1. The agent versions affected.
2. The public or MPL source supporting the behavior.
3. The request and response fixtures used for validation.
4. Whether any MPL-covered expression was copied.
5. The test demonstrating interoperability.

## Audit artifacts

The `audit/` directory contains:

- `LICENSE-AUDIT-1.14.2.md`: human-readable findings.
- `licenses-1.14.2.csv`: one row for every tracked upstream file.
- `tools/license_audit.py`: the report generator used after ScanCode.

The canonical CSV contains 1,799 unique tracked paths, SHA-256 hashes,
detected and effective license conclusions, evidence, and confidence levels.
One hundred files were conservatively marked for manual review. Those files
must not be imported without a separate review.

The operational procedure, contributor declarations, and accidental-exposure
response are defined in [CLEAN-ROOM-POLICY.md](CLEAN-ROOM-POLICY.md).
