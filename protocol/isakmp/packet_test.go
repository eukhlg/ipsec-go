package isakmp

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestMainModeSAFixture(t *testing.T) {
	wire := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0, 0, 0, 0, 0, 0, 0, 0,
		1, 0x10, 2, 0,
		0, 0, 0, 0,
		0, 0, 0, 72,
		0, 0, 0, 44,
		0, 0, 0, 1, 0, 0, 0, 1,
		0, 0, 0, 32,
		1, ProtocolIKE, 0, 1,
		0, 0, 0, 24,
		1, TransformIKE, 0, 0,
		0x80, 1, 0, 7,
		0x80, 2, 0, 2,
		0x80, 3, 0, 1,
		0x80, 4, 0, 2,
	}
	p, err := DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if p.Exchange != ExchangeIdentityProtect || len(p.Payloads) != 1 {
		t.Fatalf("packet=%#v", p)
	}
	sa, ok := p.Payloads[0].(SecurityAssociation)
	if !ok || sa.DOI != DOIIPsec || sa.Situation != SituationIdentityOnly || len(sa.Proposals) != 1 || len(sa.Proposals[0].Transforms) != 1 {
		t.Fatalf("SA=%#v", p.Payloads[0])
	}
	if got := sa.Proposals[0].Transforms[0].Attributes; len(got) != 4 || got[0].Value != EncryptionAESCBC || got[3].Value != DHGroup2 {
		t.Fatalf("attributes=%#v", got)
	}
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, wire) {
		t.Fatalf("fixture changed:\n got %x\nwant %x", encoded, wire)
	}
}

func TestPacketPayloadRoundTrip(t *testing.T) {
	want := Packet{
		InitiatorCookie: Cookie{1, 2, 3}, ResponderCookie: Cookie{4, 5, 6},
		Exchange: ExchangeInformational, MessageID: 0x10203040,
		Payloads: []Payload{
			DataPayload{Kind: PayloadNonce, Data: []byte{1, 2, 3}},
			Identification{IDType: IDFQDN, ProtocolID: 17, Port: 1701, Data: []byte("vpn.example")},
			Certificate{Encoding: 4, Data: []byte{0xaa}},
			CertificateRequest{Encoding: 4, Authority: []byte{0xbb}},
			Notification{DOI: DOIIPsec, ProtocolID: ProtocolESP, SPI: []byte{1, 2, 3, 4}, MessageType: 24576, Data: []byte{9}},
			Delete{DOI: DOIIPsec, ProtocolID: ProtocolESP, SPIs: [][]byte{{1, 2, 3, 4}, {5, 6, 7, 8}}},
			NATOriginalAddress{Kind: PayloadNATOA, IDType: IDIPv4Address, Address: []byte{192, 0, 2, 1}},
			UnknownPayload{Kind: 200, Data: []byte{7, 8}},
		},
	}
	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != VersionIKEv1 {
		t.Fatalf("version=%x", got.Version)
	}
	want.Version = VersionIKEv1
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v\nwant=%#v", got, want)
	}
}

func TestEncryptedPacketIsOpaque(t *testing.T) {
	want := Packet{InitiatorCookie: Cookie{1}, ResponderCookie: Cookie{2}, Exchange: ExchangeQuickMode, Flags: FlagEncrypted, MessageID: 7, FirstPayload: PayloadHash, EncryptedPayload: []byte{0xde, 0xad, 0xbe, 0xef}}
	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	want.Version = VersionIKEv1
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
}

func TestDecodeRejectsMalformedPackets(t *testing.T) {
	valid, err := (Packet{Exchange: ExchangeInformational, Payloads: []Payload{DataPayload{Kind: PayloadNonce, Data: []byte{1}}}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		wire   []byte
		target error
	}{
		{"short-header", valid[:20], ErrShortPacket},
		{"bad-version", mutate(valid, 17, 0x20), ErrBadVersion},
		{"reserved-flags", mutate(valid, 19, 0x80), ErrInvalidPacket},
		{"wrong-length", mutate(valid, 27, byte(len(valid)+1)), ErrInvalidPacket},
		{"payload-reserved", mutate(valid, 29, 1), ErrInvalidPayload},
		{"payload-length-small", mutate(valid, 31, 3), ErrInvalidPayload},
		{"trailing-without-payload", packetWithUnchainedByte(), ErrInvalidPacket},
		{"top-level-proposal", topLevelProposalPacket(), ErrInvalidPayload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodePacket(tc.wire)
			if !errors.Is(err, tc.target) {
				t.Fatalf("got %v, want %v", err, tc.target)
			}
		})
	}
}

func topLevelProposalPacket() []byte {
	wire := make([]byte, 32)
	wire[16] = byte(PayloadProposal)
	wire[17] = VersionIKEv1
	wire[18] = byte(ExchangeIdentityProtect)
	wire[27] = byte(len(wire))
	wire[30], wire[31] = 0, 4
	return wire
}

func packetWithUnchainedByte() []byte {
	wire := make([]byte, 29)
	wire[17] = VersionIKEv1
	wire[18] = byte(ExchangeInformational)
	wire[27] = byte(len(wire))
	wire[28] = 1
	return wire
}

func mutate(in []byte, index int, value byte) []byte {
	out := append([]byte(nil), in...)
	out[index] = value
	return out
}

func TestMarshalRejectsInvalidEncryptedPacket(t *testing.T) {
	_, err := (Packet{Flags: FlagEncrypted, FirstPayload: PayloadHash}).MarshalBinary()
	if !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("err=%v", err)
	}
}
