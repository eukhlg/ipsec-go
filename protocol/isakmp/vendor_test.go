package isakmp

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestDetectPeerCapabilities(t *testing.T) {
	caps := DetectPeerCapabilities([]Payload{DataPayload{Kind: PayloadVendorID, Data: VendorNATTRFC3947}, DataPayload{Kind: PayloadVendorID, Data: VendorMicrosoftL2TP}, DataPayload{Kind: PayloadVendorID, Data: VendorDPDRFC3706}})
	if !caps.NATTRFC3947 || !caps.MicrosoftL2TP || !caps.DPD || caps.NATTDraft {
		t.Fatalf("caps=%#v", caps)
	}
}

func TestNATDHashAndDetection(t *testing.T) {
	ci, cr := Cookie{1}, Cookie{2}
	local := netip.MustParseAddrPort("192.0.2.1:500")
	remote := netip.MustParseAddrPort("198.51.100.2:500")
	localHash, err := NATDHash(HashSHA1, ci, cr, local)
	if err != nil {
		t.Fatal(err)
	}
	remoteHash, _ := NATDHash(HashSHA1, ci, cr, remote)
	if bytes.Equal(localHash, remoteHash) || len(localHash) != 20 {
		t.Fatalf("hashes=%x/%x", localHash, remoteHash)
	}
	payloads := []Payload{DataPayload{Kind: PayloadNATD, Data: remoteHash}, DataPayload{Kind: PayloadNATD, Data: localHash}}
	detection, err := DetectNAT(HashSHA1, ci, cr, local, remote, payloads)
	if err != nil || detection.LocalNAT || detection.RemoteNAT {
		t.Fatalf("detection=%#v err=%v", detection, err)
	}
	payloads[0] = DataPayload{Kind: PayloadNATD, Data: bytes.Repeat([]byte{9}, 20)}
	detection, _ = DetectNAT(HashSHA1, ci, cr, local, remote, payloads)
	if !detection.RemoteNAT || detection.LocalNAT {
		t.Fatalf("detection=%#v", detection)
	}
}
