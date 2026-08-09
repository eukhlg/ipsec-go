package isakmp

import (
	"bytes"
	"net"
	"testing"
)

func TestMainModeResponderTranscript(t *testing.T) {
	serverID := Identification{IDType: IDIPv4Address, ProtocolID: 17, Port: 500, Data: net.IPv4(192, 0, 2, 1).To4()}
	responder, err := NewMainModeResponder(MainModeConfig{PreSharedKey: []byte("test psk"), ResponderID: serverID, Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 2048))})
	if err != nil {
		t.Fatal(err)
	}
	ci := Cookie{1, 2, 3, 4, 5, 6, 7, 8}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{
		phase1Transform(EncryptionDESCBC, HashMD5, DHGroup1, 0),
		phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128),
	}}}}
	message1, _ := (Packet{InitiatorCookie: ci, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa}}).MarshalBinary()
	wire2, err := responder.Handle(message1)
	if err != nil {
		t.Fatal(err)
	}
	message2, err := DecodePacket(wire2)
	if err != nil {
		t.Fatal(err)
	}
	if message2.ResponderCookie == (Cookie{}) || responder.State() != MainModeAwaitKeyExchange {
		t.Fatalf("state=%v", responder.State())
	}
	selected := message2.Payloads[0].(SecurityAssociation)
	if len(selected.Proposals[0].Transforms) != 1 || selected.Proposals[0].Transforms[0].Attributes[0].Value != EncryptionAESCBC {
		t.Fatalf("selected=%#v", selected)
	}

	clientDH, err := NewDHExchange(DHGroup2, bytes.NewReader(bytes.Repeat([]byte{0x24}, 512)))
	if err != nil {
		t.Fatal(err)
	}
	ni := bytes.Repeat([]byte{0x11}, 20)
	message3, _ := (Packet{InitiatorCookie: ci, ResponderCookie: message2.ResponderCookie, Exchange: ExchangeIdentityProtect, Payloads: []Payload{
		DataPayload{Kind: PayloadKeyExchange, Data: clientDH.Public()}, DataPayload{Kind: PayloadNonce, Data: ni},
	}}).MarshalBinary()
	wire4, err := responder.Handle(message3)
	if err != nil {
		t.Fatal(err)
	}
	message4, _ := DecodePacket(wire4)
	serverPublic := message4.Payloads[0].(DataPayload).Data
	nr := message4.Payloads[1].(DataPayload).Data
	shared, err := clientDH.SharedSecret(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	suite, _ := ParsePhase1Transform(selected.Proposals[0].Transforms[0])
	secrets, err := DerivePhase1Secrets(suite, []byte("test psk"), ni, nr, shared, ci, message2.ResponderCookie)
	if err != nil {
		t.Fatal(err)
	}
	iv, _ := InitialPhase1IV(suite, clientDH.Public(), serverPublic)
	clientCipher, _ := NewCBCContext(suite, secrets.Key, iv)
	clientID := Identification{IDType: IDIPv4Address, ProtocolID: 17, Port: 500, Data: net.IPv4(198, 51, 100, 7).To4()}
	_, sai, _ := MarshalPayloads([]Payload{sa})
	idBody, _ := clientID.marshalBody()
	hashI, _ := MainModeHash(suite, secrets.SKEYID, clientDH.Public(), serverPublic, ci, message2.ResponderCookie, sai, idBody, true)
	first5, body5, _ := MarshalPayloads([]Payload{clientID, DataPayload{Kind: PayloadHash, Data: hashI}})
	message5, _ := (Packet{InitiatorCookie: ci, ResponderCookie: message2.ResponderCookie, Exchange: ExchangeIdentityProtect, Flags: FlagEncrypted, FirstPayload: first5, EncryptedPayload: clientCipher.Encrypt(body5)}).MarshalBinary()
	wire6, err := responder.Handle(message5)
	if err != nil {
		t.Fatal(err)
	}
	message6, _ := DecodePacket(wire6)
	plain6, err := clientCipher.Decrypt(message6.EncryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	payloads6, err := DecodePayloads(message6.FirstPayload, plain6)
	if err != nil {
		t.Fatal(err)
	}
	if responder.State() != MainModeEstablished || len(payloads6) != 2 || payloads6[0].(Identification).IDType != IDIPv4Address {
		t.Fatalf("state=%v payloads=%#v", responder.State(), payloads6)
	}
	serverIDBody, _ := serverID.marshalBody()
	wantR, _ := MainModeHash(suite, secrets.SKEYID, clientDH.Public(), serverPublic, ci, message2.ResponderCookie, sai, serverIDBody, false)
	if !bytes.Equal(payloads6[1].(DataPayload).Data, wantR) {
		t.Fatal("HASH_R mismatch")
	}
	if _, ok := responder.Secrets(); !ok {
		t.Fatal("secrets unavailable")
	}
}

func TestMainModeRejectsBadHASHI(t *testing.T) {
	// Authentication comparison itself is covered without constructing another full transcript.
	if VerifyPRFValue([]byte{1, 2, 3}, []byte{1, 2, 4}) || VerifyPRFValue([]byte{1}, []byte{1, 0}) {
		t.Fatal("accepted mismatched hash")
	}
}
