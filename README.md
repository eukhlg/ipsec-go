# ipsec-go

An embeddable Go IKEv1/IPsec implementation, used by
[Overture VPN](https://github.com/eukhlg/overture-vpn).

- IKEv1 Main Mode with pre-shared-key authentication and Quick Mode
- ESP transport mode, integrity verification, replay protection, and SA lifetimes
- NAT-T over UDP/4500 and raw ESP listeners
- DPD, authenticated deletion, overlapping child SAs, and IKE ownership transfer
- Injected packet connections, packet handlers, and lifecycle callbacks

Packages:

| Package | Responsibility |
| --- | --- |
| `protocol/isakmp` | IKEv1 codecs, cryptography, exchanges, and control plane |
| `protocol/esp` | ESP protection, replay checks, and NAT-T framing |
| `server` | IKE and ESP listeners, opaque association registry, and packet callbacks |

`ESPRegistry.Open` returns authenticated plaintext and an opaque `Association`.
Use `Seal` for replies, `Replacement` to follow a rekey, and `Cookie` or
`BelongsToIKE` to coordinate lifecycle handling. Raw and NAT-T transports call
an `ESPPacketHandler`; its `Dispatch` callback runs after protocol replies are
sent. Applications own the decrypted payload's protocol policy and session routing.

Packet buffers and batched UDP I/O come from
[netio](https://github.com/eukhlg/netio). This module does not depend on L2TP,
PPP, TUN, TOML, or Docker. Its current
negotiation policy is focused on the IKEv1 transport-mode use case; extraction
does not add IKEv2, tunnel mode, or arbitrary traffic-selector support.

The implementation has not had an independent security audit. Existing
interoperability results do not establish production security or scale.

Run `GOWORK=off go test ./...` to test the library independently. Releases use
`v`-prefixed semantic versions, starting with
[v0.1.0](https://github.com/eukhlg/ipsec-go/releases/tag/v0.1.0).

The relevant history was extracted from the original combined l2tp-go project;
Overture VPN retains the complete application history.
