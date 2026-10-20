# Bounded encrypted sender: full VPN throughput comparison — 20 October 2026

**Reference limitation:** the requested original-settings matrix below contains
strongSwan replay-window losses. A matched-window AES-128 control found much
higher reference throughput; see the diagnostic section at the end. Treat the
main table as original/default-setting results, not a tuned capacity ranking.

Measured receiver TCP goodput, **Mbit/s**, arithmetic means of two trials.
Upload means client → VPN server; download means VPN server → client.

| ESP cipher | Transport | Our upload | Our download | strongSwan upload | strongSwan download |
|---|---|---:|---:|---:|---:|
| AES-128-CBC | Raw ESP | 512.6 | 787.8 | 758.7 | 747.0 |
| AES-128-CBC | NAT-T | 505.9 | 697.6 | 700.6 | 727.9 |
| AES-192-CBC | Raw ESP | 502.3 | 772.9 | 710.9 | 686.8 |
| AES-192-CBC | NAT-T | 538.4 | 731.0 | 747.8 | 652.0 |
| AES-256-CBC | Raw ESP | 487.5 | 712.9 | 693.7 | 747.5 |
| AES-256-CBC | NAT-T | 512.8 | 724.1 | 668.6 | 656.9 |
| 3DES-CBC | Raw ESP | 168.4 | 170.3 | 125.2 | 129.2 |
| 3DES-CBC | NAT-T | 169.9 | 169.5 | 128.7 | 127.3 |

## Individual-trial ranges

| ESP cipher | Transport | Our upload | Our download | strongSwan upload | strongSwan download |
|---|---|---:|---:|---:|---:|
| AES-128-CBC | Raw ESP | 507.6–517.6 | 781.8–793.8 | 752.2–765.3 | 716.5–777.5 |
| AES-128-CBC | NAT-T | 505.3–506.4 | 682.7–712.5 | 674.7–726.4 | 673.1–782.7 |
| AES-192-CBC | Raw ESP | 500.7–503.9 | 772.4–773.5 | 705.8–716.1 | 673.3–700.3 |
| AES-192-CBC | NAT-T | 536.2–540.5 | 727.4–734.6 | 688.6–807.1 | 633.0–670.9 |
| AES-256-CBC | Raw ESP | 481.1–493.8 | 695.7–730.1 | 609.7–777.6 | 737.3–757.7 |
| AES-256-CBC | NAT-T | 511.5–514.1 | 721.0–727.3 | 593.4–743.8 | 644.4–669.4 |
| 3DES-CBC | Raw ESP | 168.1–168.7 | 170.2–170.4 | 124.5–125.9 | 129.1–129.3 |
| 3DES-CBC | NAT-T | 167.7–172.0 | 168.3–170.7 | 126.9–130.4 | 124.6–129.9 |

## Exact sources and implementation

- Application: `4c5cddb905662c7f5be7d42d7ee2f0695c690ffb`.
- IPsec: `25a512ad75695fa2efe3c6574fe103fa4152c750`.
- L2TP: `d617ab9b8f21925cd37b1bfe55533e3fcb09dd7b`.
- Built with Go 1.25.4, Linux ARM64, CGO disabled, using frozen local source
  snapshots and go.work. This is the current implementation, not the older
  published testing image or the earlier experimental sender patch.
- Production path: TUN read → framing → ESP sealing → bounded ciphertext FIFO
  (64 packets) → separate socket sender. Single-buffer ESP assembly is retained.
- Queued work carries its retained association and is checked before enqueue and
  transmission. This report measures current behavior; it is not a new code change.
- Current default inbound replay window is 1024 packets. Earlier app benchmarks
  used older revisions with a smaller window; changes across dates cannot be
  attributed exclusively to queue placement. Client/reference use their same
  strongSwan defaults as the original benchmark.

## Matched test conditions

Apple M1 Max; shared ARM64 Docker Desktop Linux VM, 10 vCPUs. Same client for
every case: strongSwan 5.9.13 + xl2tpd 1.3.18 + pppd 2.5.0. Reference server:
the same strongSwan/xl2tpd/pppd versions using Linux kernel ESP and PPPoL2TP.
The current Go executable is copied into the same helper container image to
keep supporting runtime tools consistent. No experimental code or profiling
hooks were added. Binary build information and hash are saved in results/.

- IKEv1 Main Mode, PSK; IKE AES-128/SHA-1/MODP2048; no Phase 2 PFS.
- ESP transport mode: AES-128/192/256-CBC or 3DES-CBC, HMAC-SHA1-96.
- Raw ESP and forced NAT-T format; directly connected Docker bridge without an
  actual NAT gateway or host port publishing.
- PPP PAP; MTU 1400; one client and one TCP stream; iperf3 3.17.1.
- Two trials per direction, each 10 measured seconds after 2 omitted seconds:
  `iperf3 -c 10.77.0.1 -t 10 -O 2 -J`, adding `-R` for download.
- Same duration/trial count as most rows of the original benchmark; the earlier
  AES-256 raw-ESP rerun had three trials, which is not pooled into this report.
- iperf terminates at server inner address 10.77.0.1; client is 10.77.0.2. This
  measures VPN endpoints, not forwarding/NAT to a third machine.
- All tests run sequentially. Builds, race tests and module microbenchmarks
  completed before timed iperf trials.
- Verified negotiated cipher, encapsulation, PPP address, and nonzero encrypted
  traffic counters. LAN bypass is disabled. Kernel XFRM counters are preserved.

## Interpretation and limits

Short single-client runs in a shared VM are sensitive to scheduling, thermal and
virtual-network effects. Individual ranges and retransmission counts should be
considered along with means. They do not establish capacity on physical hosts,
scaling with clients, WAN performance, latency, or results on other CPUs. All
cipher rows are fresh measurements rather than extrapolations from AES-128.

The isolated module result is recorded separately: outbound Seal allocations
remain eight per packet. A pipeline throughput gain comes from overlapping
sealing and sending, not making SA.Seal itself execute in parallel.

## Published evidence and reproduction

This is a results-only publication: reports, raw measurements, negotiated-SA
logs, kernel counters, build metadata and validation output. Executable runners,
source patches and binaries are not included.

- [Environment and source revisions](environment.json)
- [Raw application results](app-results/)
- [CSV summary](app-results/summary.csv)
- [Module benchmark](../bounded-sender-queue-2026-10-20.md)

Reproduce using the source revisions and matched test conditions above. The
application build command is:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o overture-vpn ./app/cmd/overture-vpn
```

Run each cipher/transport against a separate strongSwan/xl2tpd reference server,
using the same client and the iperf commands recorded above. The saved JSON
includes per-trial settings, timestamps, TCP statistics and receiver goodput.

## Replay-window diagnostic and matched control

The requested original-settings matrix above retains the same strongSwan defaults
as earlier runs. However, all eight strongSwan cases recorded client kernel
`XfrmInStateSeqError` replay rejections (about 20,000–24,000 per AES case,
about 1,100–1,200 for 3DES). The app cases recorded zero client kernel errors.
This limits interpretation of that matrix as a maximum-throughput comparison.

A diagnostic AES-128 NAT-T rerun increased only the client's receive replay
window to 1024 packets. Download increased to about 1,383 Mbit/s and client
replay rejections disappeared, while the server still recorded upload-side
replay rejections. A final matched control set 1024-packet receive windows on
both endpoints, retaining replay protection and all other benchmark conditions.
The app already uses a 1024-packet server window, so its control changed only
the strongSwan client's window. Kernel-installed 1024-packet windows were
verified without recording SA keys. Two trials per direction were used.

| Control, AES-128 NAT-T | Upload, Mbit/s | Download, Mbit/s | Client replay rejections | Server replay rejections |
|---|---:|---:|---:|---:|
| strongSwan, client window 1024 only | 722.5 | 1383.0 | 0 | 30552 |
| strongSwan, both windows 1024 | 1388.7 | 1404.9 | 0 | 0 |
| Our app, both windows 1024 | 538.4 | 698.4 | 0 | N/A — userspace ESP |

The matched control shows that the new pipeline improves app download versus
the earlier app build, but the apparent proximity to the original-settings
strongSwan reference should not be interpreted as matching tuned kernel IPsec
throughput. The current app achieved about 698 Mbit/s download versus about
1,405 Mbit/s for the reference with matched receive windows. No tuned-window
results for the other ciphers are inferred or substituted into the main matrix.

strongSwan documents a default replay window of 32 packets and support for
larger windows with Netlink: [strongSwan 5.9 configuration](https://docs.strongswan.org/docs/5.9/config/strongswanConf.html).
Kernel counters do not distinguish every replay-rejection cause; the window
control provides direct evidence that window configuration materially affected
these measurements.

Control raw files and counters are under [client-only control](app-results/replay-control/),
[matched app control](app-results/matched-control-go/), and
[matched strongSwan control](app-results/matched-control-strongswan/). See the
[control summary](app-results/control-summary.json).
