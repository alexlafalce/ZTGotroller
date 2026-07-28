# Memory benchmark

## Preliminary baseline

An initial idle measurement was taken on July 28, 2026 on Linux x86-64 using
GNU `time` and local listeners. The cold run included identity and state
creation; the warm run reused those files:

| Executable | Cold maximum RSS | Warm maximum RSS | Binary size |
| --- | ---: | ---: | ---: |
| ZTGotroller, Go 1.25.12 | 16,292 KiB | 12,788 KiB | 14,940,190 bytes |
| ZeroTier One 1.14.2 | 11,288 KiB | 11,200 KiB | 27,388,504 bytes |

In these short preliminary runs, the Go controller used about 44% more maximum
resident memory during cold initialization and about 14% more with reused
state, while its executable was about 45% smaller. This is a baseline, not a
performance conclusion: the ZeroTier executable is a full node and neither
process had equivalent controller state or traffic.

## Release comparison protocol

The final comparison must use:

- the same host, kernel, architecture, cgroup limits, and sampling tool;
- release builds without race instrumentation;
- identical warm-up and measurement periods;
- equivalent network, member, route, rule, and authorization counts;
- identical configuration-request rates and packet sizes;
- idle, steady request, burst, and post-GC/quiescent phases;
- at least five isolated runs per case; and
- median, p95, peak RSS, proportional set size where available, CPU time,
  allocation rate, GC cycles, and binary size.

Report the complete commands, commits, Go version, compiler flags, raw samples,
and whether the historical executable ran only its controller or the full node.
Track Go heap metrics separately from process RSS so SQLite, stacks, mappings,
and allocator retention remain visible.

Memory is an operational compatibility goal, not a language contest. A larger
Go baseline can still be acceptable if it provides safer maintenance and
predictable scaling, but regressions must be measured and explained.

## Reproducible state-load harness

[`scripts/memory-benchmark.sh`](../scripts/memory-benchmark.sh) loads both
controllers through their historical HTTP API with the same number of private
networks and authorized members, waits for a warm-up interval, and samples RSS
and PSS from `/proc`. It writes the raw time series, per-run peaks, and binary
sizes as CSV files:

```sh
go build -trimpath -ldflags='-s -w' -o ./bin/ztgotroller ./cmd/ztgotroller
ZTGOTROLLER_BIN="$PWD/bin/ztgotroller" \
ZEROTIER_1142_BIN=/absolute/path/to/zerotier-one-1.14.2 \
OUTPUT="$PWD/memory-results" \
./scripts/memory-benchmark.sh
```

The defaults are 10 networks, 100 members per network, a 10-second warm-up,
30 seconds of sampling, and five isolated runs. `NETWORKS`,
`MEMBERS_PER_NETWORK`, `WARMUP_SECONDS`, `SAMPLE_SECONDS`, and `RUNS` can
override them. The historical binary must be the audited 1.14.2 build and must
support its local controller API.

The harness measures equivalent persisted controller state. It deliberately
does not claim equivalent packet load, CPU, Go heap allocations, or GC cycles;
those require a separate agent-driven lab phase under the release comparison
protocol above.

## Equivalent state-load result

A complete five-run state-load comparison was performed on July 28, 2026 at
ZTGotroller commit `c57760b515a721286a1755e6a56592a7927d1540`:

| Executable | Median peak RSS | Mean peak RSS | Median peak PSS | Mean peak PSS | Binary size |
| --- | ---: | ---: | ---: | ---: | ---: |
| ZTGotroller | 22,676 KiB | 22,605.6 KiB | 21,176 KiB | 21,106.4 KiB | 10,432,768 bytes |
| ZeroTier One 1.14.2 | 16,556 KiB | 16,550.4 KiB | 12,024 KiB | 12,009.2 KiB | 27,388,504 bytes |

Each run loaded 10 private networks and 100 authorized members per network
through the historical API, warmed for 10 seconds, and sampled for 31 seconds.
There were five isolated runs per executable (310 total samples). The host was
Linux `6.18.33.2-microsoft-standard-WSL2` x86-64; ZTGotroller was compiled by
Go 1.25.12 using `-trimpath -ldflags='-s -w -buildid='`.

At this state size, ZTGotroller's median peak RSS was about 37% higher and its
median peak PSS about 76% higher than the 1.14.2 full-node process, while its
binary was about 62% smaller. The per-run peaks are retained under
[`benchmarks/memory/2026-07-28`](../benchmarks/memory/2026-07-28). These numbers
remain a controller-state comparison, not the agent-driven packet-load result
required for a final performance characterization.
