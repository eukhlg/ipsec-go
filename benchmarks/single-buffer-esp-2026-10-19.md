# Single-buffer ESP sealing — 19 October 2026

`SA.Seal` now assembles the ESP header, IV, padded payload, and ICV trailer in
one owned output buffer. CBC encryption operates in place on the payload region.
Per-packet IV generation, HMAC construction, SA locking, sequence handling,
and lifetime accounting retain their existing behavior.

## Local before/after measurements

Apple M1 Max, macOS ARM64, Go 1.25.4. AES-128-CBC with HMAC-SHA1-96 and real
crypto/rand IVs. Each value is the median of three benchmark runs. Setup is
excluded from timing; each operation seals one payload through the same SA.

| Payload | Metric | Before | After | Change |
| --- | --- | ---: | ---: | ---: |
| 64 bytes | Time per seal | 997.8 ns | 897.4 ns | −10.1% |
| 64 bytes | Allocated bytes per seal | 1,480 | 1,112 | −24.9% |
| 64 bytes | Allocations per seal | 12 | 8 | −33.3% |
| 1,400 bytes | Time per seal | 3,542 ns | 2,956 ns | −16.5% |
| 1,400 bytes | Allocated bytes per seal | 7,400 | 2,520 | −65.9% |
| 1,400 bytes | Allocations per seal | 12 | 8 | −33.3% |

Reproduce the benchmark from this module:

```sh
go test ./protocol/esp -run '^$' -bench BenchmarkSeal -benchmem -count 3
```

These are isolated sealing measurements, not VPN download throughput. The earlier
Linux ARM64/Docker experiment measured 399.4 → 414.4 Mbit/s (+3.8%) for the
single-buffer prototype. That experiment is recorded in Overture VPN's local
`benchmarks/download-investigation-2026-10-19/REPORT.md`; end-to-end throughput
was not rerun for this implementation. The asynchronous sender experiment is
outside this change.

## Validation

- Library and Overture VPN application race-test suites passed in the shared workspace.
- `go vet` passed for both modules.
- Existing RFC3602 known-answer, authentication, replay, and lifetime tests passed.
- Added regression coverage for AES-128/192/256 and 3DES padding boundaries,
  empty payloads, independent output ownership, and IV-read failure state rollback.

The output assembly uses one packet buffer; CBC and HMAC still allocate their
own internal state, accounting for the remaining allocations.
