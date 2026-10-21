# UDP message batching

`udptransport.Conn` borrows caller-owned `Message` slices. `Write` returns the
successfully transmitted prefix; retry only the remainder on positive progress
without an error. Errors are terminal in the application sender. Zero progress
is `io.ErrNoProgress`. The API never releases payloads. Use one reader and one
writer at a time; socket ownership and deadlines remain with the caller.

Batches contain at most **32** messages. Linux unconnected `*net.UDPConn` uses
`golang.org/x/net/ipv4` or `ipv6` `ReadBatch`/`WriteBatch` (recvmmsg/sendmmsg),
following wireguard-go's socket approach, without GSO/GRO or ancillary offloads.
IPv4, IPv6 and dual-stack listeners are supported. Other platforms, connected
UDP sockets and injected/wrapped PacketConns use a single message per operation.
ENOSYS/EOPNOTSUPP with no progress permanently disables the respective batch
operation and immediately retries through the single-message path. Other errors
propagate, preserving the existing terminal socket-error policy.

`Read` reports only returned messages. Callers discard `Truncated`, invalid
lengths, and unreturned slots. UDP fallback uses ReadMsgUDP to check MSG_TRUNC
(or the Winsock receive error); generic PacketConn cannot expose flags and
conservatively rejects full-buffer reads. The NAT-T server allocates 32 separate
pooled maximum-packet buffers on Linux (about 2 MiB per listener), or one on the
fallback path. Each handler and synchronous Dispatch borrows one buffer until
completion; used storage is erased before reuse and all buffers released on exit.
The existing one-second deadline preserves cancellation and IKE maintenance.

NAT-T classification is unchanged: keepalives are discarded, Non-ESP-Marker IKE
is routed to the control plane, and ESP receives no added/removed marker. Control
replies and synchronous handler replies retain their existing single writes.
Raw ESP stays on its original PacketConn transport. Cryptography, TUN and replay
processing are unchanged.

The app sender takes the first queued packet, immediately drains at most 31
additional available entries, and never waits for more packets or a timer. It
groups adjacent NAT-T messages only, retaining global FIFO ordering across raw
and UDP traffic and per-SA ordering. It checks every unsent SA before each write,
including retries after partial writes. Positive progress advances to the next
unsent message. Errors reject the unsent local batch and queue, close sockets,
unblock producers and release each accepted buffer once. Cancellation and revoked
SAs also release accepted buffers; failed enqueue retains producer ownership.
The default queue remains 64 entries plus at most 32 in the local batch.

Validation and matched measurements are in the sibling app repository at
`benchmarks/udp-batching-2026-10-20/README.md`. Both repositories use branch
`codex/udp-batching`. The workspace requires this library checkout; the app's
existing published dependency does not yet contain these APIs.
