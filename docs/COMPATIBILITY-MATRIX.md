# Agent compatibility matrix

The release gate covers these real-agent cases:

| Case | Agent set | Required observation |
| --- | --- | --- |
| `join-1.14.2` | audited 1.14.2 | joins, is authorized, and reaches `OK` |
| `join-current` | current MPL release | joins, is authorized, and reaches `OK` |
| `mixed-peer-connectivity` | both | both reach `OK` and exchange bidirectional peer traffic |

The most recently recorded successful manual run is documented in
[INTEROPERABILITY.md](INTEROPERABILITY.md). A new release must attach fresh
machine-readable evidence rather than treating that historical result as
permanent.

## Automated runner

[`scripts/compatibility-matrix.sh`](../scripts/compatibility-matrix.sh) executes
all three cases and produces `summary.csv` plus a separate evidence directory
and driver log for each case:

```sh
ZTGOTROLLER_BIN=/opt/zt-lab/ztgotroller \
ZEROTIER_1142_BIN=/opt/zt-lab/zerotier-one-1.14.2 \
ZEROTIER_CURRENT_BIN=/opt/zt-lab/zerotier-one-current \
ZT_INTEROP_DRIVER=/opt/zt-lab/run-case \
OUTPUT="$PWD/compatibility-results" \
./scripts/compatibility-matrix.sh
```

The driver is deliberately external because the isolated lab's private planet
identity, network namespace setup, and privileged interface operations must
not be committed to this repository. It receives:

- `--case NAME`, `--controller PATH`, and `--output DIRECTORY`;
- one or more `--agent LABEL=PATH` arguments;
- one or more `--expect-join LABEL` assertions; and
- `--expect-bidirectional-peer-traffic` for the mixed case.

The driver must return zero only after checking the asserted observations and
must store its agent versions, controller commit, commands, network status,
assigned addresses, and traffic evidence in the output directory. The wrapper
runs every case even after a failure and returns nonzero if any case failed.

This separation prevents an unprivileged unit test or packet fixture from being
reported as real end-to-end agent compatibility.
