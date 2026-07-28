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
