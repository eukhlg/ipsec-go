# ESP sealing after bounded-sender support — 20 October 2026

The bounded encrypted-datagram sender lives in Overture VPN, where it overlaps
ESP sealing with socket transmission. ipsec-go supplies independently owned
ciphertext and retained-association validity checks. An isolated `SA.Seal`
benchmark measures sealing cost, not asynchronous pipeline throughput.

## Repeated local module measurements

Apple M1 Max, macOS ARM64, Go 1.25.4. AES-128-CBC/HMAC-SHA1-96 with real
crypto/rand IVs. Medians of three benchmark runs, one SA per sub-benchmark;
setup excluded. Both revisions already contain single-buffer ESP encoding.

- Before: `4480587c57143bba2b0828a63b0eb7d07a2e1f9e`.
- After: `25a512ad75695fa2efe3c6574fe103fa4152c750`.

| Payload | Metric | Before | After | Change |
|---|---|---:|---:|---:|
| 64 bytes | Time per seal (ns) | 897.9 | 881 | -1.9% |
| 64 bytes | Allocated bytes per seal | 1112 | 1112 | +0.0% |
| 64 bytes | Allocations per seal | 8 | 8 | +0.0% |
| 1,400 bytes | Time per seal (ns) | 3000 | 2894 | -3.5% |
| 1,400 bytes | Allocated bytes per seal | 2520 | 2520 | +0.0% |
| 1,400 bytes | Allocations per seal | 8 | 8 | +0.0% |

`SA.Seal`'s timed implementation is unchanged between these revisions. The
small timing differences are not evidence of a queue-related crypto speedup;
allocation counts and bytes are unchanged. The corresponding application
throughput report measures complete VPN traffic with the queue enabled; see
[full cipher matrix and replay-window controls](bounded-sender-queue-2026-10-20/app-throughput.md).

The current library also supports configurable inbound replay windows. That
change is not exercised by outbound-only Seal timing; the application comparison
uses its current default of 1024 packets. This benchmark is not an inbound
replay-processing measurement.

## Reproduction

At each revision, run from this module with Go 1.25.4:

```sh
GOWORK=off go test ./protocol/esp -run '^$' -bench BenchmarkSeal -benchmem -count 3
```

See [raw module benchmark output](bounded-sender-queue-2026-10-20/) and
[single-buffer ESP report](single-buffer-esp-2026-10-19.md). Revisions were
snapshotted into temporary directories; production source was not modified.
All three current workspace repositories passed their race-test suites before
the end-to-end runs.
