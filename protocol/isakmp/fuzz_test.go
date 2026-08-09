package isakmp

import "testing"

func FuzzDecodePacket(f *testing.F) {
	seed, err := (Packet{Exchange: ExchangeIdentityProtect, Payloads: []Payload{SecurityAssociation{
		DOI: DOIIPsec, Situation: SituationIdentityOnly,
		Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{{Number: 1, ID: TransformIKE, Attributes: []Attribute{TVAttribute(AttributeP1DHGroup, DHGroup2)}}}}}},
	}}).MarshalBinary()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		packet, err := DecodePacket(wire)
		if err != nil {
			return
		}
		encoded, err := packet.MarshalBinary()
		if err != nil {
			t.Fatalf("decoded packet cannot be encoded: %v", err)
		}
		if _, err := DecodePacket(encoded); err != nil {
			t.Fatalf("encoded packet cannot be decoded: %v", err)
		}
	})
}

func FuzzParseTransforms(f *testing.F) {
	seed, err := phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128).marshalBody()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		transform, err := decodeTransform(body)
		if err != nil {
			return
		}
		_, _ = ParsePhase1Transform(transform)
		_, _ = ParseESPTransform(transform)
	})
}
