package isakmp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestQuickModeResponderTranscript(t *testing.T) {
	phase1 := Phase1Transform{Encryption: EncryptionAESCBC, Hash: HashSHA1, AuthMethod: AuthPreSharedKey, DHGroup: DHGroup2, KeyBits: 128}
	secrets := Phase1Secrets{SKEYIDa: bytes.Repeat([]byte{0x11}, 20), SKEYIDd: bytes.Repeat([]byte{0x22}, 20), Key: bytes.Repeat([]byte{0x33}, 16)}
	ci, cr := Cookie{1}, Cookie{2}
	lastBlock := bytes.Repeat([]byte{0x44}, 16)
	responder, err := NewQuickModeResponder(QuickModeConfig{Transform: phase1, Secrets: secrets, InitiatorCookie: ci, ResponderCookie: cr, LastPhase1Block: lastBlock, Random: bytes.NewReader(bytes.Repeat([]byte{0x55}, 512))})
	if err != nil {
		t.Fatal(err)
	}
	messageID := uint32(0x10203040)
	iv, _ := Phase2IV(phase1, lastBlock, messageID)
	clientCipher, _ := NewCBCContext(phase1, secrets.Key, iv)
	esp := Transform{Number: 1, ID: TransformESPAES, Attributes: []Attribute{
		TVAttribute(AttributeP2Encapsulation, EncapsulationTransport), TVAttribute(AttributeP2Authentication, ESPAuthHMACSHA196), TVAttribute(AttributeP2KeyLength, 128),
	}}
	offeredSPI := []byte{0x01, 0x02, 0x03, 0x04}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolESP, SPI: offeredSPI, Transforms: []Transform{esp}}}}
	ni := bytes.Repeat([]byte{0x66}, 20)
	idci := Identification{IDType: IDIPv4Address, ProtocolID: 17, Port: 1701, Data: []byte{192, 0, 2, 10}}
	idcr := Identification{IDType: IDIPv4Address, ProtocolID: 17, Port: 1701, Data: []byte{192, 0, 2, 1}}
	after := []Payload{sa, DataPayload{Kind: PayloadNonce, Data: ni}, idci, idcr}
	_, afterWire, _ := MarshalPayloads(after)
	hash1, _ := QuickModeHash1(phase1, secrets.SKEYIDa, messageID, afterWire)
	first1, body1, _ := MarshalPayloads(append([]Payload{DataPayload{Kind: PayloadHash, Data: hash1}}, after...))
	request1, _ := (Packet{InitiatorCookie: ci, ResponderCookie: cr, Exchange: ExchangeQuickMode, Flags: FlagEncrypted, MessageID: messageID, FirstPayload: first1, EncryptedPayload: clientCipher.Encrypt(body1)}).MarshalBinary()
	wire2, err := responder.Handle(request1)
	if err != nil {
		t.Fatal(err)
	}
	response2, _ := DecodePacket(wire2)
	plain2, err := clientCipher.Decrypt(response2.EncryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	payloads2, meaningful, err := decodePayloadsWithLength(response2.FirstPayload, plain2)
	if err != nil {
		t.Fatal(err)
	}
	hashPayload := payloads2[0].(DataPayload)
	hashLength := int(binary.BigEndian.Uint16(plain2[2:4]))
	wantHash2, _ := QuickModeHash2(phase1, secrets.SKEYIDa, messageID, ni, plain2[hashLength:meaningful])
	if !bytes.Equal(hashPayload.Data, wantHash2) {
		t.Fatal("HASH(2) mismatch")
	}
	selected := payloads2[1].(SecurityAssociation)
	if len(payloads2) != 5 || payloads2[3].(Identification).Port != 1701 || payloads2[4].(Identification).Port != 1701 {
		t.Fatalf("selectors were not echoed: %#v", payloads2)
	}
	if bytes.Equal(selected.Proposals[0].SPI, offeredSPI) {
		t.Fatal("responder reused initiator SPI")
	}
	nr := payloads2[2].(DataPayload).Data
	hash3, _ := QuickModeHash3(phase1, secrets.SKEYIDa, messageID, ni, nr)
	first3, body3, _ := MarshalPayloads([]Payload{DataPayload{Kind: PayloadHash, Data: hash3}})
	request3, _ := (Packet{InitiatorCookie: ci, ResponderCookie: cr, Exchange: ExchangeQuickMode, Flags: FlagEncrypted, MessageID: messageID, FirstPayload: first3, EncryptedPayload: clientCipher.Encrypt(body3)}).MarshalBinary()
	reply3, err := responder.Handle(request3)
	if err != nil || reply3 != nil {
		t.Fatalf("reply=%x err=%v", reply3, err)
	}
	pair, ok := responder.Pair()
	if !ok {
		t.Fatal("pair unavailable")
	}
	if pair.Outbound.SPI != binary.BigEndian.Uint32(offeredSPI) || pair.Inbound.SPI != binary.BigEndian.Uint32(selected.Proposals[0].SPI) || len(pair.Inbound.EncryptionKey) != 16 || len(pair.Inbound.AuthenticationKey) != 20 {
		t.Fatalf("pair=%#v", pair)
	}
}

func TestQuickModeRejectsUnsafeSelectorAndClearsState(t *testing.T) {
	phase1 := Phase1Transform{Encryption: EncryptionAESCBC, Hash: HashSHA1, AuthMethod: AuthPreSharedKey, DHGroup: DHGroup2, KeyBits: 128}
	secrets := Phase1Secrets{SKEYIDa: bytes.Repeat([]byte{0x11}, 20), SKEYIDd: bytes.Repeat([]byte{0x22}, 20), Key: bytes.Repeat([]byte{0x33}, 16)}
	lastBlock := bytes.Repeat([]byte{0x44}, 16)
	responder, err := NewQuickModeResponder(QuickModeConfig{Transform: phase1, Secrets: secrets, InitiatorCookie: Cookie{1}, ResponderCookie: Cookie{2}, LastPhase1Block: lastBlock, Random: bytes.NewReader(bytes.Repeat([]byte{0x55}, 512))})
	if err != nil {
		t.Fatal(err)
	}
	messageID := uint32(7)
	espTransform := Transform{Number: 1, ID: TransformESPAES, Attributes: []Attribute{TVAttribute(AttributeP2Encapsulation, EncapsulationTransport), TVAttribute(AttributeP2Authentication, ESPAuthHMACSHA196), TVAttribute(AttributeP2KeyLength, 128)}}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{espTransform}}}}
	ni := DataPayload{Kind: PayloadNonce, Data: bytes.Repeat([]byte{0x66}, 20)}
	badID := Identification{IDType: IDIPv4Address, ProtocolID: 6, Port: 22, Data: []byte{192, 0, 2, 10}}
	after := []Payload{sa, ni, badID, badID}
	_, afterWire, _ := MarshalPayloads(after)
	hash1, _ := QuickModeHash1(phase1, secrets.SKEYIDa, messageID, afterWire)
	first, body, _ := MarshalPayloads(append([]Payload{DataPayload{Kind: PayloadHash, Data: hash1}}, after...))
	iv, _ := Phase2IV(phase1, lastBlock, messageID)
	cipher, _ := NewCBCContext(phase1, secrets.Key, iv)
	wire, _ := (Packet{InitiatorCookie: Cookie{1}, ResponderCookie: Cookie{2}, Exchange: ExchangeQuickMode, Flags: FlagEncrypted, MessageID: messageID, FirstPayload: first, EncryptedPayload: cipher.Encrypt(body)}).MarshalBinary()
	if _, err := responder.Handle(wire); err == nil || responder.State() != QuickModeFailed {
		t.Fatalf("state=%d error=%v", responder.State(), err)
	}
	if _, ok := responder.Pair(); ok {
		t.Fatal("failed exchange exposed an ESP pair")
	}
}

func TestQuickModeDoesNotSelectNATTBeforePortMigration(t *testing.T) {
	transform := Transform{Number: 1, ID: TransformESPAES, Attributes: []Attribute{
		TVAttribute(AttributeP2Encapsulation, EncapsulationNATTTransport),
		TVAttribute(AttributeP2Authentication, ESPAuthHMACSHA196),
		TVAttribute(AttributeP2KeyLength, 128),
	}}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{transform}}}}
	if _, _, _, _, err := selectESPsa(sa, bytes.NewReader(bytes.Repeat([]byte{1}, 32))); err != ErrUnsupportedTransform {
		t.Fatalf("error=%v", err)
	}
}
