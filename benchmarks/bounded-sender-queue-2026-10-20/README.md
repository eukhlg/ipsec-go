# Bounded-sender benchmark evidence

- [Module report](../bounded-sender-queue-2026-10-20.md)
- [Application/strongSwan report and replay-window controls](app-throughput.md)
- [Module baseline raw output](before.txt)
- [Module current raw output](after.txt)
- [Application raw measurements](app-results/)
- [Environment and source revisions](environment.json)

The application report retains the original/default-setting cipher matrix and
separately reports a matched 1024-packet replay-window control. The default
strongSwan results experienced replay rejections and should not be treated as
a tuned throughput ceiling. All figures are local single-client measurements.

This directory contains results only; no executable code or binaries are included.
