package isakmp

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestSecurityAssociationRoundTrip(t *testing.T) {
	want := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{
		{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{
			{Number: 1, ID: TransformIKE, Attributes: []Attribute{
				TVAttribute(AttributeP1Encryption, EncryptionAESCBC),
				TVAttribute(AttributeP1Hash, HashSHA1),
				TVAttribute(AttributeP1AuthMethod, AuthPreSharedKey),
				TVAttribute(AttributeP1DHGroup, DHGroup14),
				TVAttribute(AttributeP1KeyLength, 256),
				TLVAttribute(AttributeP1LifeValue, []byte{0, 0, 0x70, 0x80}),
			}},
			{Number: 2, ID: TransformIKE, Attributes: []Attribute{TVAttribute(AttributeP1Encryption, Encryption3DESCBC)}},
		}},
	}}
	p := Packet{Exchange: ExchangeIdentityProtect, Payloads: []Payload{want}}
	wire, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Payloads[0].(SecurityAssociation)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
}

func TestProposalRejectsTransformCountMismatch(t *testing.T) {
	// SA header, one proposal claiming two transforms but carrying one.
	body := []byte{
		0, 0, 0, 1, 0, 0, 0, 1,
		0, 0, 0, 16,
		1, ProtocolIKE, 0, 2,
		0, 0, 0, 8,
		1, TransformIKE, 0, 0,
	}
	_, err := decodeSA(body)
	if !errors.Is(err, ErrInvalidPayload) && !errors.Is(err, ErrShortPacket) {
		t.Fatalf("err=%v", err)
	}
}

func TestTransformRejectsTruncatedTLV(t *testing.T) {
	_, err := decodeTransform([]byte{1, TransformIKE, 0, 0, 0, 12, 0, 4, 1})
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("err=%v", err)
	}
}

func TestAttributeWireEncodings(t *testing.T) {
	tv, err := TVAttribute(4, 14).marshal()
	if err != nil {
		t.Fatal(err)
	}
	tlv, err := TLVAttribute(12, []byte{1, 2, 3, 4}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tv, []byte{0x80, 4, 0, 14}) || !bytes.Equal(tlv, []byte{0, 12, 0, 4, 1, 2, 3, 4}) {
		t.Fatalf("tv=%x tlv=%x", tv, tlv)
	}
}

func TestMarshalRejectsNestedLengthOverflow(t *testing.T) {
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{
		Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{{
			Number: 1, ID: TransformIKE, Attributes: []Attribute{TLVAttribute(AttributeP1LifeValue, make([]byte, 65535))},
		}},
	}}}
	_, err := (Packet{Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("err=%v", err)
	}
}
