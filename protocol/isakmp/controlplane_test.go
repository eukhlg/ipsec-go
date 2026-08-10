package isakmp

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestControlPlaneCreatesReplaysAndExpiresSA(t *testing.T) {
	control, err := NewControlPlane(ControlPlaneConfig{PreSharedKey: []byte("psk"), ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 1024)), MaxPhase1SAs: 1, Phase1Lifetime: time.Minute, HandshakeTimeout: time.Minute})
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

func TestControlPlaneHonorsNegotiatedPhase1Lifetime(t *testing.T) {
	control, err := NewControlPlane(ControlPlaneConfig{PreSharedKey: []byte("psk"), ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x66}, 1024)), MaxPhase1SAs: 1, Phase1Lifetime: time.Hour, HandshakeTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	transform := phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)
	transform.Attributes = append(transform.Attributes, TVAttribute(AttributeP1LifeType, LifeTypeSeconds), TVAttribute(AttributeP1LifeValue, 1))
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{transform}}}}
	request, _ := (Packet{InitiatorCookie: Cookie{1}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}
	now := time.Unix(1, 0)
	if _, err := control.HandleDatagram(peer, request, now); err != nil {
		t.Fatal(err)
	}
	request2, _ := (Packet{InitiatorCookie: Cookie{2}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	if _, err := control.HandleDatagram(peer, request2, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestControlSAResponseCacheIsBounded(t *testing.T) {
	sa := &controlSA{responses: make(map[string][]byte)}
	for i := byte(0); i < 10; i++ {
		sa.cacheResponse([]byte{i}, []byte{i + 1})
	}
	if len(sa.responses) != 8 || len(sa.responseOrder) != 8 {
		t.Fatalf("responses=%d order=%d", len(sa.responses), len(sa.responseOrder))
	}
	if _, ok := sa.responses[string([]byte{0})]; ok {
		t.Fatal("old response was not evicted")
	}
	if got := sa.responses[string([]byte{9})]; !bytes.Equal(got, []byte{10}) {
		t.Fatalf("reply=%x", got)
	}
}
