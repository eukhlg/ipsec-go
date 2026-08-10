package server

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"l2tp-go/protocol/esp"
	"l2tp-go/protocol/isakmp"
	"l2tp-go/protocol/l2tp"
)

func TestNATTServerProtectedL2TPHandshake(t *testing.T) {
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	registry := NewESPRegistry()
	engine := NewEngine(Config{HostName: "server"})
	bridge, _ := NewESPBridge(engine, registry)
	listener, err := ListenNATT("127.0.0.1:0", bridge)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- listener.Serve(ctx) }()
	client, err := net.DialUDP("udp", nil, listener.Conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := registry.Install(client.LocalAddr(), pair); err != nil {
		t.Fatal(err)
	}
	clientOut, _ := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 256))})
	clientIn, _ := esp.NewSA(esp.SAConfig{SPI: pair.Outbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Outbound.EncryptionKey, AuthenticationKey: pair.Outbound.AuthenticationKey})
	sccrq := l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true), l2tp.StringAVP(l2tp.AttrHostName, "client", true), l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true), l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true), l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 77, true)}}
	channel := l2tp.NewControlChannel(0, 1)
	l2tpWire, _ := channel.Queue(sccrq, time.Now())
	protected, _ := clientOut.Seal(encodeUDP(40000, 1701, l2tpWire), esp.IPProtocolUDP)
	_, _ = client.Write(esp.EncapsulateNATTESP(protected))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 4096)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	kind, payload := esp.ClassifyNATT(buffer[:n])
	if kind != esp.NATTESP {
		t.Fatalf("kind=%d", kind)
	}
	udp, _, err := clientIn.Open(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, _, reply, err := decodeUDP(udp)
	if err != nil {
		t.Fatal(err)
	}
	message, err := l2tp.DecodeControlMessage(reply)
	if err != nil || message.Type != l2tp.SCCRP {
		t.Fatalf("message=%#v err=%v", message, err)
	}
	cancel()
	_ = listener.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}
