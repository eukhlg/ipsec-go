package server

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/isakmp"
)

func TestIKEServerSurvivesMalformedDatagramAndReplies(t *testing.T) {
	server, err := ListenIKE("127.0.0.1:0", isakmp.ControlPlaneConfig{PreSharedKey: []byte("psk"), ResponderID: isakmp.Identification{IDType: isakmp.IDIPv4Address, Data: []byte{127, 0, 0, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x78}, 1024))})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := net.DialUDP("udp", nil, server.Conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = client.Write([]byte{1, 2, 3})
	transform := isakmp.Transform{Number: 1, ID: isakmp.TransformIKE, Attributes: []isakmp.Attribute{
		isakmp.TVAttribute(isakmp.AttributeP1Encryption, isakmp.EncryptionAESCBC),
		isakmp.TVAttribute(isakmp.AttributeP1Hash, isakmp.HashSHA1),
		isakmp.TVAttribute(isakmp.AttributeP1AuthMethod, isakmp.AuthPreSharedKey),
		isakmp.TVAttribute(isakmp.AttributeP1DHGroup, isakmp.DHGroup2),
		isakmp.TVAttribute(isakmp.AttributeP1KeyLength, 128),
	}}
	sa := isakmp.SecurityAssociation{DOI: isakmp.DOIIPsec, Situation: isakmp.SituationIdentityOnly, Proposals: []isakmp.Proposal{
		{Number: 1, ProtocolID: isakmp.ProtocolIKE, Transforms: []isakmp.Transform{transform}},
	}}
	request, _ := (isakmp.Packet{InitiatorCookie: isakmp.Cookie{1}, Exchange: isakmp.ExchangeIdentityProtect, Payloads: []isakmp.Payload{sa}}).MarshalBinary()
	_, _ = client.Write(request)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 2048)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := isakmp.DecodePacket(buffer[:n])
	if err != nil || packet.ResponderCookie == (isakmp.Cookie{}) {
		t.Fatalf("packet=%#v err=%v", packet, err)
	}
	cancel()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}
