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
	after := []Payload{sa, DataPayload{Kind: PayloadNonce, Data: ni}}
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
