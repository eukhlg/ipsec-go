package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/esp"
	"github.com/eukhlg/l2tp-go/protocol/isakmp"
	"github.com/eukhlg/l2tp-go/protocol/l2tp"
)

func testESPPair(encapsulation uint16) isakmp.ESPPair {
	return isakmp.ESPPair{Transform: isakmp.ESPTransform{Encryption: isakmp.TransformESPAES, Authentication: isakmp.ESPAuthHMACSHA196, Encapsulation: encapsulation, KeyBits: 128}, Inbound: isakmp.ESPDirectionalKeys{SPI: 0x11111111, EncryptionKey: bytes.Repeat([]byte{1}, 16), AuthenticationKey: bytes.Repeat([]byte{2}, 20)}, Outbound: isakmp.ESPDirectionalKeys{SPI: 0x22222222, EncryptionKey: bytes.Repeat([]byte{3}, 16), AuthenticationKey: bytes.Repeat([]byte{4}, 20)}}
}

func TestESPBridgeProtectedL2TPHandshake(t *testing.T) {
	pair := testESPPair(isakmp.EncapsulationTransport)
	pair.ResponderCookie = isakmp.Cookie{9}
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	registry := NewESPRegistry()
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	bridge, err := NewESPBridge(NewEngine(Config{HostName: "server"}), registry)
	if err != nil {
		t.Fatal(err)
	}
	var activityCount int
	var activityCookie isakmp.Cookie
	var activityAt time.Time
	bridge.SetAuthenticatedActivityHandler(func(cookie isakmp.Cookie, now time.Time) {
		activityCount++
		activityCookie, activityAt = cookie, now
	})
	clientOutbound, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey, Random: bytes.NewReader(bytes.Repeat([]byte{5}, 256))})
	if err != nil {
		t.Fatal(err)
	}
	clientInbound, _ := esp.NewSA(esp.SAConfig{SPI: pair.Outbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Outbound.EncryptionKey, AuthenticationKey: pair.Outbound.AuthenticationKey})
	sccrq := l2tp.ControlMessage{Type: l2tp.SCCRQ, AVPs: []l2tp.AVP{l2tp.Uint16AVP(l2tp.AttrProtocolVersion, 0x0100, true), l2tp.StringAVP(l2tp.AttrHostName, "client", true), l2tp.Uint32AVP(l2tp.AttrFramingCap, 3, true), l2tp.Uint32AVP(l2tp.AttrBearerCap, 3, true), l2tp.Uint16AVP(l2tp.AttrAssignedTunnelID, 77, true)}}
	clientControl := l2tp.NewControlChannel(0, 1)
	l2tpWire, err := clientControl.Queue(sccrq, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	protected, err := clientOutbound.Seal(encodeUDP(40000, 1701, l2tpWire), esp.IPProtocolUDP)
	if err != nil {
		t.Fatal(err)
	}
	result, err := bridge.Handle(peer, protected, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if activityCount != 1 || activityCookie != pair.ResponderCookie || !activityAt.Equal(time.Unix(1, 0)) {
		t.Fatalf("activity count=%d cookie=%x at=%s", activityCount, activityCookie, activityAt)
	}
	if len(result.Datagrams) != 1 {
		t.Fatalf("datagrams=%d", len(result.Datagrams))
	}
	udp, next, err := clientInbound.Open(result.Datagrams[0].Payload)
	if err != nil || next != esp.IPProtocolUDP {
		t.Fatalf("next=%d err=%v", next, err)
	}
	source, destination, reply, err := decodeUDP(udp)
	if err != nil || source != 1701 || destination != 40000 {
		t.Fatalf("ports=%d/%d err=%v", source, destination, err)
	}
	message, err := l2tp.DecodeControlMessage(reply)
	if err != nil || message.Type != l2tp.SCCRP {
		t.Fatalf("message=%#v err=%v", message, err)
	}
	if _, err := bridge.Handle(peer, protected, time.Unix(2, 0)); err != esp.ErrReplay {
		t.Fatalf("replay error=%v", err)
	}
	if activityCount != 1 {
		t.Fatalf("replayed ESP refreshed activity: count=%d", activityCount)
	}
}

func TestESPRegistryRejectsPeerAndMarksNATT(t *testing.T) {
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	registry := NewESPRegistry()
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	client, _ := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey, Random: bytes.NewReader(bytes.Repeat([]byte{6}, 256))})
	wire, _ := client.Seal(encodeUDP(40000, 1701, []byte{1}), esp.IPProtocolUDP)
	if _, err := registry.lookup(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 11), Port: 4500}, wire); err != ErrESPPeer {
		t.Fatalf("error=%v", err)
	}
}

func TestESPRegistryRekeyOverlapAndLifecycleRemoval(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	cookie := isakmp.Cookie{9}
	first := testESPPair(isakmp.EncapsulationNATTTransport)
	first.ResponderCookie = cookie
	second := testESPPair(isakmp.EncapsulationNATTTransport)
	second.ResponderCookie = cookie
	second.Inbound.SPI, second.Outbound.SPI = 0x33333333, 0x44444444
	registry := NewESPRegistry()
	if err := registry.Install(peer, first); err != nil {
		t.Fatal(err)
	}
	if err := registry.Install(peer, second); err != nil {
		t.Fatal(err)
	}
	if registry.Count() != 2 {
		t.Fatalf("overlapping SAs=%d", registry.Count())
	}
	registry.Remove(first.Outbound.SPI)
	if registry.Count() != 1 {
		t.Fatalf("paired removal left %d SAs", registry.Count())
	}
	registry.RemoveIKE(cookie)
	if registry.Count() != 0 {
		t.Fatalf("IKE removal left %d SAs", registry.Count())
	}
}

func TestESPRegistryRebindPreservesChildWhenPredecessorIsRemoved(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	oldCookie := isakmp.Cookie{1}
	newCookie := isakmp.Cookie{2}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	pair.ResponderCookie = oldCookie
	registry := NewESPRegistry()
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	registry.mu.RLock()
	session := registry.bySPI[pair.Inbound.SPI]
	registry.mu.RUnlock()

	registry.RebindIKE(oldCookie, newCookie)
	registry.RemoveIKE(oldCookie)
	if registry.Count() != 1 || session.revoked.Load() || session.ikeCookie != newCookie {
		t.Fatalf("count=%d revoked=%v cookie=%x", registry.Count(), session.revoked.Load(), session.ikeCookie)
	}
	registry.RemoveIKE(newCookie)
	if registry.Count() != 0 || !session.revoked.Load() {
		t.Fatalf("count=%d revoked=%v", registry.Count(), session.revoked.Load())
	}
}

func TestESPBridgeMovesFlowToReplacementSAAfterDelete(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	logicalPeer := &net.UDPAddr{IP: peer.IP, Port: 40000}
	cookie := isakmp.Cookie{9}
	first := testESPPair(isakmp.EncapsulationNATTTransport)
	first.ResponderCookie = cookie
	second := testESPPair(isakmp.EncapsulationNATTTransport)
	second.ResponderCookie = cookie
	second.Inbound.SPI, second.Outbound.SPI = 0x33333333, 0x44444444
	registry := NewESPRegistry()
	if err := registry.Install(peer, first); err != nil {
		t.Fatal(err)
	}
	bridge, err := NewESPBridge(NewEngine(Config{HostName: "server"}), registry)
	if err != nil {
		t.Fatal(err)
	}
	registry.mu.RLock()
	oldSession := registry.bySPI[first.Inbound.SPI]
	registry.mu.RUnlock()
	bridge.flows[logicalPeer.String()] = espFlow{session: oldSession, peer: peer, clientPort: 40000}
	if err := registry.Install(peer, second); err != nil {
		t.Fatal(err)
	}
	registry.Remove(first.Outbound.SPI)

	datagram, err := bridge.SealL2TP(logicalPeer, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("seal after rekey: %v", err)
	}
	if got := binary.BigEndian.Uint32(datagram.Payload[:4]); got != second.Outbound.SPI {
		t.Fatalf("outbound SPI=%08x want=%08x", got, second.Outbound.SPI)
	}
}
