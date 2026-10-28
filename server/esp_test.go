package server

import (
	"bytes"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	"github.com/eukhlg/netio/packetbuf"
	"net"
	"testing"
)

func testESPPair(encapsulation uint16) isakmp.ESPPair {
	return isakmp.ESPPair{Transform: isakmp.ESPTransform{Encryption: isakmp.TransformESPAES, Authentication: isakmp.ESPAuthHMACSHA196, Encapsulation: encapsulation, KeyBits: 128}, Inbound: isakmp.ESPDirectionalKeys{SPI: 0x11111111, EncryptionKey: bytes.Repeat([]byte{1}, 16), AuthenticationKey: bytes.Repeat([]byte{2}, 20)}, Outbound: isakmp.ESPDirectionalKeys{SPI: 0x22222222, EncryptionKey: bytes.Repeat([]byte{3}, 16), AuthenticationKey: bytes.Repeat([]byte{4}, 20)}}
}

func TestESPRegistryRejectsPeerAndMarksNATT(t *testing.T) {
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	registry := NewESPRegistry()
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	client, _ := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey, Random: bytes.NewReader(bytes.Repeat([]byte{6}, 256))})
	wire, _ := client.Seal([]byte{1}, esp.IPProtocolUDP)
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

func TestRegistryRejectsUnownedAssociation(t *testing.T) {
	registry := NewESPRegistry()
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	for _, association := range []*Association{nil, {}, {owner: NewESPRegistry()}} {
		if _, err := registry.Seal(association, peer, []byte{1}, esp.IPProtocolUDP); err != ErrUnknownESP {
			t.Fatalf("invalid association seal: %v", err)
		}
		if registry.Replacement(association) != nil {
			t.Fatal("invalid association has replacement")
		}
	}
}

func TestRegistryOpenSealWithoutL2TP(t *testing.T) {
	registry := NewESPRegistry()
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	inbound, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey})
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := esp.NewSA(esp.SAConfig{SPI: pair.Outbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Outbound.EncryptionKey, AuthenticationKey: pair.Outbound.AuthenticationKey})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := inbound.Seal([]byte("opaque payload"), 6)
	if err != nil {
		t.Fatal(err)
	}
	association, payload, next, err := registry.Open(peer, wire)
	if err != nil || next != 6 || string(payload) != "opaque payload" {
		t.Fatalf("open: %q %d %v", payload, next, err)
	}
	reply, err := registry.Seal(association, peer, []byte("opaque reply"), 6)
	if err != nil || !reply.NATT {
		t.Fatalf("seal: %v", err)
	}
	payload, next, err = outbound.Open(reply.Payload)
	if err != nil || next != 6 || string(payload) != "opaque reply" {
		t.Fatalf("reply: %q %d %v", payload, next, err)
	}
	registry.Remove(pair.Inbound.SPI)
	if _, err := registry.Seal(association, peer, nil, 6); err != ErrUnknownESP {
		t.Fatalf("revoked: %v", err)
	}
}

func TestAssociationOwnsPeerAddress(t *testing.T) {
	registry := NewESPRegistry()
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	pair.ResponderCookie = isakmp.Cookie{9}
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	registry.mu.RLock()
	association := registry.bySPI[pair.Inbound.SPI]
	registry.mu.RUnlock()
	peer.Port = 9999
	peer.IP[0] ^= 0xff
	returned := association.Peer().(*net.UDPAddr)
	if returned.Port != 4500 || !returned.IP.Equal(net.IPv4(192, 0, 2, 10)) {
		t.Fatalf("borrowed peer address: %v", returned)
	}
	returned.Port = 8888
	if association.Peer().(*net.UDPAddr).Port != 4500 {
		t.Fatal("mutable exported peer address")
	}
	if NewESPRegistry().Cookie(association) != (isakmp.Cookie{}) {
		t.Fatal("foreign registry exposed cookie")
	}
}

func TestRegistryReserveSealBuffer(t *testing.T) {
	registry := NewESPRegistry()
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	if err := registry.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	inbound, _ := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey})
	outbound, _ := esp.NewSA(esp.SAConfig{SPI: pair.Outbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Outbound.EncryptionKey, AuthenticationKey: pair.Outbound.AuthenticationKey})
	wire, _ := inbound.Seal([]byte("hello"), 6)
	association, _, _, err := registry.Open(peer, wire)
	if err != nil {
		t.Fatal(err)
	}
	// Reserve in order, seal in reverse order, deliver in reservation order.
	var seals []ESPSeal
	for i := 0; i < 3; i++ {
		buffer, _ := packetbuf.Copy([]byte{byte(i), 1, 2})
		seal, err := registry.ReserveSealBuffer(association, peer, buffer, 6)
		if err != nil {
			t.Fatal(err)
		}
		seals = append(seals, seal)
	}
	datagrams := make([]ESPDatagram, len(seals))
	for i := len(seals) - 1; i >= 0; i-- {
		datagrams[i] = seals[i].Seal()
	}
	for i, d := range datagrams {
		if !d.NATT || d.Peer != peer || d.Buffer == nil {
			t.Fatalf("datagram %d metadata %+v", i, d)
		}
		payload, next, err := outbound.Open(d.Payload)
		if err != nil || next != 6 || payload[0] != byte(i) {
			t.Fatalf("datagram %d: %v %d %v", i, payload, next, err)
		}
		d.Release()
	}
	registry.Remove(pair.Inbound.SPI)
	buffer, _ := packetbuf.Copy([]byte{1})
	if _, err := registry.ReserveSealBuffer(association, peer, buffer, 6); err != ErrUnknownESP {
		t.Fatalf("revoked: %v", err)
	}
	buffer.Release()
}
