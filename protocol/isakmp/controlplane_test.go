package isakmp

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestControlPlaneCreatesReplaysAndExpiresSA(t *testing.T) {
	control, err := NewControlPlane(ControlPlaneConfig{PreSharedKey: []byte("psk"), ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 1024)), MaxPhase1SAs: 1, Phase1Lifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)}}}}
	request, _ := (Packet{InitiatorCookie: Cookie{1}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}
	now := time.Unix(1, 0)
	first, err := control.HandleDatagram(peer, request, now)
	if err != nil || len(first.Reply) == 0 {
		t.Fatalf("reply=%x err=%v", first.Reply, err)
	}
	replay, err := control.HandleDatagram(peer, request, now.Add(time.Second))
	if err != nil || !bytes.Equal(replay.Reply, first.Reply) {
		t.Fatalf("replay=%x err=%v", replay.Reply, err)
	}
	secondRequest, _ := (Packet{InitiatorCookie: Cookie{2}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	if _, err := control.HandleDatagram(peer, secondRequest, now.Add(2*time.Second)); !errors.Is(err, ErrSALimit) {
		t.Fatalf("error=%v", err)
	}
	if _, err := control.HandleDatagram(peer, secondRequest, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if control.SACount() != 1 {
		t.Fatalf("SAs=%d", control.SACount())
	}
}
