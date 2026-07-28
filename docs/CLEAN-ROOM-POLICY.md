# Clean-room development policy

## Purpose

ZTGotroller is an independent controller implementation for sustainable
self-hosting. This policy reduces provenance and licensing risk by keeping
restricted controller material outside the design and implementation process.
It supplements, but does not replace, advice from qualified legal counsel.

## Permitted evidence

- ZeroTier One 1.14.2 controller sources at the audited Apache-2.0 baseline.
- Code expressly covered by MPL-2.0 in newer agents.
- Public protocol documentation and general product documentation.
- Behavior observed on systems the contributor is authorized to test.
- Independently authored packet fixtures, interoperability tests, and API
  client tests.
- Public issue reports and agent release notes that describe externally
  observable behavior without disclosing restricted controller expression.

Copying expression from MPL-covered files creates MPL obligations for the
covered files. Prefer independent Go implementations based on documented or
observed behavior.

## Prohibited implementation sources

- `nonfree/` or any later source-available/commercial controller code.
- Diffs, commits, patches, decompilations, leaked material, or private
  documentation for restricted controllers.
- Controller-specific changelogs or release notes used as a technical
  specification for a fix.
- Summaries, tickets, prompts, or requirements that reproduce restricted
  implementation details.
- Material received under confidentiality or incompatible contractual terms.

Reading a public changelog is not automatically a license violation. The
project nevertheless excludes controller-specific restricted changelogs from
the implementation workflow because they weaken the evidence of independent
development. General knowledge that a compatibility problem exists must be
confirmed and specified through permitted evidence before work begins.

## Required provenance record

Every compatibility pull request must identify:

1. the externally observable problem;
2. the affected versions;
3. each permitted source or experiment used;
4. fixtures or tests demonstrating behavior;
5. copied expression, if any, and its license; and
6. the contributor's clean-room declaration.

Repository history is part of the audit trail. Do not combine provenance
records with unrelated changes.

## Accidental exposure

If a contributor encounters prohibited material:

1. Stop implementation and do not circulate the material.
2. Record the affected topic, files, branch, and people exposed without copying
   restricted content into public issues.
3. Notify the maintainers privately.
4. Quarantine the affected implementation and do not merge it.
5. Have an unexposed contributor derive requirements from permitted black-box
   evidence and implement them independently.
6. Obtain legal review when exposure could materially affect provenance.

Deleting a contaminated commit does not erase knowledge already acquired.
The response must account for people as well as files.

## Reviews and enforcement

Maintainers may reject a technically correct change when its provenance is
unclear. False declarations, concealed sources, or repeated boundary violations
are grounds to close a contribution and revoke repository access.

ZeroTier names and protocol identifiers may be needed for compatibility, but
trademarks and logos are not licensed by the Apache-2.0 code license. Do not
imply affiliation, endorsement, or sponsorship.
