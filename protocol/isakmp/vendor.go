package isakmp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
)

var (
	VendorNATTRFC3947   = mustVendor("4a131c81070358455c5728f20e95452f")
	VendorNATTDraft03   = mustVendor("7d9419a65310ca6f2c179d9215529d56")
	VendorNATTDraft02   = mustVendor("90cb80913ebb696e086381b5ec427b1f")
	VendorDPDRFC3706    = mustVendor("afcad71368a1f1c96b8696fc77570100")
	VendorMicrosoftL2TP = mustVendor("4048b7d56ebce88525e7de7f00d6c2d3")
)

type PeerCapabilities struct{ NATTRFC3947, NATTDraft, DPD, MicrosoftL2TP bool }

func DetectPeerCapabilities(payloads []Payload) PeerCapabilities {
	var caps PeerCapabilities
	for _, payload := range payloads {
		data, ok := payload.(DataPayload)
		if !ok || data.Kind != PayloadVendorID {
			continue
		}
		switch hex.EncodeToString(data.Data) {
		case hex.EncodeToString(VendorNATTRFC3947):
			caps.NATTRFC3947 = true
		case hex.EncodeToString(VendorNATTDraft03), hex.EncodeToString(VendorNATTDraft02):
			caps.NATTDraft = true
		case hex.EncodeToString(VendorDPDRFC3706):
			caps.DPD = true
		case hex.EncodeToString(VendorMicrosoftL2TP):
			caps.MicrosoftL2TP = true
		}
	}
	return caps
}

// NATDHash computes RFC 3947 HASH(CKY-I | CKY-R | IP | Port).
func NATDHash(hashAlgorithm uint16, initiatorCookie, responderCookie Cookie, endpoint netip.AddrPort) ([]byte, error) {
	if !endpoint.IsValid() || !endpoint.Addr().Is4() {
		return nil, fmt.Errorf("%w: NAT-D endpoint", ErrInvalidCryptoInput)
	}
	hashFunc, err := (Phase1Transform{Hash: hashAlgorithm}).hashFunc()
	if err != nil {
		return nil, err
	}
	h := hashFunc()
	_, _ = h.Write(initiatorCookie[:])
	_, _ = h.Write(responderCookie[:])
	address := endpoint.Addr().As4()
	_, _ = h.Write(address[:])
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], endpoint.Port())
	_, _ = h.Write(port[:])
	return h.Sum(nil), nil
}

type NATDetection struct{ LocalNAT, RemoteNAT bool }

func DetectNAT(hashAlgorithm uint16, initiatorCookie, responderCookie Cookie, local, remote netip.AddrPort, payloads []Payload) (NATDetection, error) {
	localHash, err := NATDHash(hashAlgorithm, initiatorCookie, responderCookie, local)
	if err != nil {
		return NATDetection{}, err
	}
	remoteHash, err := NATDHash(hashAlgorithm, initiatorCookie, responderCookie, remote)
	if err != nil {
		return NATDetection{}, err
	}
	localSeen, remoteSeen := false, false
	for _, payload := range payloads {
		data, ok := payload.(DataPayload)
		if !ok || (data.Kind != PayloadNATD && data.Kind != PayloadNATDDraft) {
			continue
		}
		encoded := hex.EncodeToString(data.Data)
		localSeen = localSeen || encoded == hex.EncodeToString(localHash)
		remoteSeen = remoteSeen || encoded == hex.EncodeToString(remoteHash)
	}
	return NATDetection{LocalNAT: !localSeen, RemoteNAT: !remoteSeen}, nil
}

func mustVendor(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}
