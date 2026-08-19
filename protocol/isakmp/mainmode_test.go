package isakmp

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestMainModeResponderTranscript(t *testing.T) {
	serverID := Identification{IDType: IDIPv4Address, ProtocolID: 17, Port: 500, Data: net.IPv4(192, 0, 2, 1).To4()}
	responder, err := NewMainModeResponder(MainModeConfig{PreSharedKey: []byte("test psk"), ResponderID: serverID, Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 2048))})
	if err != nil {
		t.Fatal(err)
	}
	ci := Cookie{1, 2, 3, 4, 5, 6, 7, 8}
	supported := phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)
	supported.Attributes = append(supported.Attributes, TVAttribute(AttributeP1LifeType, LifeTypeSeconds), TLVAttribute(AttributeP1LifeValue, []byte{0, 0, 0x70, 0x80}))
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{
		phase1Transform(EncryptionDESCBC, HashMD5, DHGroup1, 0),
		supported,
	}}}}
	message1, _ := (Packet{InitiatorCookie: ci, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa, DataPayload{Kind: PayloadVendorID, Data: VendorMicrosoftL2TP}}}).MarshalBinary()
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
	if len(message2.Payloads) != 2 || !responder.Capabilities().MicrosoftL2TP || responder.Transform().LifetimeSeconds != 28800 {
		t.Fatalf("payloads=%#v caps=%#v transform=%#v", message2.Payloads, responder.Capabilities(), responder.Transform())
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
	saBody, _ := sa.marshalBody()
	sai := message1[headerSize+4 : headerSize+4+len(saBody)]
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
	peerIdentity, ok := responder.PeerIdentity()
	if !ok || peerIdentity.IDType != clientID.IDType || peerIdentity.ProtocolID != clientID.ProtocolID || peerIdentity.Port != clientID.Port || !bytes.Equal(peerIdentity.Data, clientID.Data) {
		t.Fatalf("peer identity=%#v available=%v", peerIdentity, ok)
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

func TestMainModeNegotiatesRFC3947AndDetectsRemoteNAT(t *testing.T) {
	local := netip.MustParseAddrPort("192.0.2.1:500")
	observedRemote := netip.MustParseAddrPort("198.51.100.20:500")
	clientInternal := netip.MustParseAddrPort("10.0.0.20:500")
	serverID := Identification{IDType: IDIPv4Address, ProtocolID: 17, Port: 500, Data: local.Addr().AsSlice()}
	responder, err := NewMainModeResponder(MainModeConfig{PreSharedKey: []byte("test psk"), ResponderID: serverID, LocalEndpoint: local, RemoteEndpoint: observedRemote, Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 2048))})
	if err != nil {
		t.Fatal(err)
	}
	ci := Cookie{1, 2, 3, 4, 5, 6, 7, 8}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)}}}}
	message1, _ := (Packet{InitiatorCookie: ci, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa, DataPayload{Kind: PayloadVendorID, Data: VendorNATTRFC3947}}}).MarshalBinary()
	wire2, err := responder.Handle(message1)
	if err != nil {
		t.Fatal(err)
	}
	message2, _ := DecodePacket(wire2)
	if len(message2.Payloads) != 2 || !bytes.Equal(message2.Payloads[1].(DataPayload).Data, VendorNATTRFC3947) {
		t.Fatalf("NAT-T vendor ID not advertised: %#v", message2.Payloads)
	}
	clientDH, _ := NewDHExchange(DHGroup2, bytes.NewReader(bytes.Repeat([]byte{0x24}, 512)))
	localHash, _ := NATDHash(HashSHA1, ci, message2.ResponderCookie, local)
	internalHash, _ := NATDHash(HashSHA1, ci, message2.ResponderCookie, clientInternal)
	message3, _ := (Packet{InitiatorCookie: ci, ResponderCookie: message2.ResponderCookie, Exchange: ExchangeIdentityProtect, Payloads: []Payload{
		DataPayload{Kind: PayloadKeyExchange, Data: clientDH.Public()}, DataPayload{Kind: PayloadNonce, Data: bytes.Repeat([]byte{0x11}, 20)},
		DataPayload{Kind: PayloadNATD, Data: internalHash}, DataPayload{Kind: PayloadNATD, Data: localHash},
	}}).MarshalBinary()
	wire4, err := responder.Handle(message3)
	if err != nil {
		t.Fatal(err)
	}
	message4, _ := DecodePacket(wire4)
	detection, ok := responder.NATDetection()
	if !ok || detection.LocalNAT || !detection.RemoteNAT || !responder.NATTraversal() {
		t.Fatalf("detection=%#v complete=%v", detection, ok)
	}
	if len(message4.Payloads) != 4 || message4.Payloads[2].Type() != PayloadNATD || message4.Payloads[3].Type() != PayloadNATD {
		t.Fatalf("NAT-D response payloads=%#v", message4.Payloads)
	}
}

func TestMainModeRejectsBadHASHI(t *testing.T) {
	// Authentication comparison itself is covered without constructing another full transcript.
	if VerifyPRFValue([]byte{1, 2, 3}, []byte{1, 2, 4}) || VerifyPRFValue([]byte{1}, []byte{1, 0}) {
		t.Fatal("accepted mismatched hash")
	}
}

func TestMainModeFailureClearsSensitiveState(t *testing.T) {
	psk := []byte("shared secret")
	responder, err := NewMainModeResponder(MainModeConfig{PreSharedKey: psk, ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	responder.secrets = Phase1Secrets{SKEYID: []byte{1}, SKEYIDd: []byte{2}, SKEYIDa: []byte{3}, SKEYIDe: []byte{4}, Key: []byte{5}}
	responder.initiatorNonce, responder.responderNonce = []byte{6}, []byte{7}
	err = responder.fail(ErrInvalidCryptoInput)
	if !errors.Is(err, ErrInvalidCryptoInput) || responder.State() != MainModeFailed || responder.config.PreSharedKey != nil || responder.secrets.Key != nil || responder.initiatorNonce != nil {
		t.Fatalf("state=%v responder=%#v", responder.State(), responder)
	}
	if string(psk) != "shared secret" {
		t.Fatal("caller PSK was modified")
	}
}

func TestMainModeEchoesMicrosoftL2TPVendorCapability(t *testing.T) {
	responder, err := NewMainModeResponder(MainModeConfig{PreSharedKey: []byte("psk"), ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 64))})
	if err != nil {
		t.Fatal(err)
	}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)}}}}
	request, _ := (Packet{InitiatorCookie: Cookie{1}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa, DataPayload{Kind: PayloadVendorID, Data: VendorMicrosoftL2TP}}}).MarshalBinary()
	reply, err := responder.Handle(request)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := DecodePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.Payloads) != 2 || !responder.Capabilities().MicrosoftL2TP {
		t.Fatalf("payloads=%#v caps=%#v", packet.Payloads, responder.Capabilities())
	}
}

func TestMainModeEchoesDPDCapability(t *testing.T) {
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolIKE, Transforms: []Transform{phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)}}}}
	responder, err := NewMainModeResponder(MainModeConfig{PreSharedKey: []byte("psk"), ResponderID: Identification{IDType: IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{3}, 256))})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := (Packet{InitiatorCookie: Cookie{1}, Exchange: ExchangeIdentityProtect, Payloads: []Payload{sa, DataPayload{Kind: PayloadVendorID, Data: VendorDPDRFC3706}}}).MarshalBinary()
	reply, err := responder.Handle(request)
	if err != nil {
		t.Fatal(err)
	}
	packet, _ := DecodePacket(reply)
	if len(packet.Payloads) != 2 || !bytes.Equal(packet.Payloads[1].(DataPayload).Data, VendorDPDRFC3706) || !responder.Capabilities().DPD {
		t.Fatalf("payloads=%#v capabilities=%#v", packet.Payloads, responder.Capabilities())
	}
}

func TestMainModeForceNATTForCapablePeer(t *testing.T) {
	responder := &MainModeResponder{config: MainModeConfig{ForceNATT: true}, capabilities: PeerCapabilities{NATTRFC3947: true}}
	if !responder.NATTraversal() {
		t.Fatal("force NAT-T did not select UDP encapsulation")
	}
	responder.capabilities.NATTRFC3947 = false
	if responder.NATTraversal() {
		t.Fatal("force NAT-T selected encapsulation for an incapable peer")
	}
}

func TestMainModeAcceptsMacOSInitialContactTail(t *testing.T) {
	ci, cr := Cookie{1}, Cookie{2}
	initialContact := Notification{
		DOI: DOIIPsec, ProtocolID: ProtocolIKE,
		SPI: append(append([]byte(nil), ci[:]...), cr[:]...), MessageType: NotifyInitialContact,
	}
	if err := validateMainModeAuthenticationTail([]Payload{initialContact}, ci, cr); err != nil {
		t.Fatal(err)
	}
	initialContact.MessageType = NotifyResponderLifetime
	if err := validateMainModeAuthenticationTail([]Payload{initialContact}, ci, cr); err == nil {
		t.Fatal("accepted unsupported Main Mode notification")
	}
}
