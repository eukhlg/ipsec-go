package isakmp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func testEstablishedMain(t *testing.T) *MainModeResponder {
	t.Helper()
	transform := Phase1Transform{Encryption: EncryptionAESCBC, Hash: HashSHA1, AuthMethod: AuthPreSharedKey, DHGroup: DHGroup2, KeyBits: 128}
	secrets := Phase1Secrets{SKEYIDa: bytes.Repeat([]byte{0x11}, 20), SKEYIDd: bytes.Repeat([]byte{0x22}, 20), Key: bytes.Repeat([]byte{0x33}, 16)}
	cipher, err := NewCBCContext(transform, secrets.Key, bytes.Repeat([]byte{0x44}, 16))
	if err != nil {
		t.Fatal(err)
	}
	return &MainModeResponder{state: MainModeEstablished, transform: transform, secrets: secrets, cipher: cipher, initiatorCookie: Cookie{1}, responderCookie: Cookie{2}}
}

func TestInformationalDPDAndDeletes(t *testing.T) {
	main := testEstablishedMain(t)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}
	sa := &controlSA{peer: addressKey(peer), main: main, quick: make(map[uint32]*QuickModeResponder), quickUpdated: make(map[uint32]time.Time), responses: make(map[string][]byte), expires: time.Now().Add(time.Hour)}
	control := &ControlPlane{config: ControlPlaneConfig{Random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 128)), HandshakeTimeout: time.Minute, QuickModeTimeout: time.Minute}, sas: map[Cookie]*controlSA{main.responderCookie: sa}}
	spi := ikeDeleteSPI(main.initiatorCookie, main.responderCookie)
	sequence := make([]byte, 4)
	binary.BigEndian.PutUint32(sequence, 9)
	dpd, _ := main.EncodeInformational(0x10203040, []Payload{Notification{DOI: DOIIPsec, ProtocolID: ProtocolIKE, SPI: spi, MessageType: NotifyRThere, Data: sequence}})
	result, err := control.HandleDatagram(peer, dpd, time.Now())
	if err != nil || len(result.Reply) == 0 {
		t.Fatalf("reply=%x error=%v", result.Reply, err)
	}
	replyID, payloads, err := main.DecodeInformational(result.Reply)
	ack := payloads[0].(Notification)
	if err != nil || replyID == 0x10203040 || ack.MessageType != NotifyRThereACK || !bytes.Equal(ack.Data, sequence) {
		t.Fatalf("id=%08x ack=%#v error=%v", replyID, ack, err)
	}

	espDelete, _ := main.EncodeInformational(2, []Payload{Delete{DOI: DOIIPsec, ProtocolID: ProtocolESP, SPIs: [][]byte{{0x11, 0x22, 0x33, 0x44}}}})
	result, err = control.HandleDatagram(peer, espDelete, time.Now())
	if err != nil || len(result.Lifecycle) != 1 || result.Lifecycle[0].Type != LifecycleDeleteESP || result.Lifecycle[0].SPIs[0] != 0x11223344 {
		t.Fatalf("result=%#v error=%v", result, err)
	}

	ikeDelete, _ := main.EncodeInformational(3, []Payload{Delete{DOI: DOIIPsec, ProtocolID: ProtocolIKE, SPIs: [][]byte{spi}}})
	result, err = control.HandleDatagram(peer, ikeDelete, time.Now())
	if err != nil || len(result.Lifecycle) != 1 || result.Lifecycle[0].Type != LifecycleDeleteIKE || control.SACount() != 0 {
		t.Fatalf("result=%#v SAs=%d error=%v", result, control.SACount(), err)
	}
}

func TestInformationalRejectsTamperedHash(t *testing.T) {
	main := testEstablishedMain(t)
	wire, _ := main.EncodeInformational(7, []Payload{Notification{DOI: DOIIPsec, ProtocolID: ProtocolIKE, SPI: ikeDeleteSPI(main.initiatorCookie, main.responderCookie), MessageType: NotifyRThere, Data: []byte{0, 0, 0, 1}}})
	wire[len(wire)-1] ^= 1
	if _, _, err := main.DecodeInformational(wire); err == nil {
		t.Fatal("tampered informational packet accepted")
	}
}

func TestControlPlaneShutdownBuildsDelete(t *testing.T) {
	main := testEstablishedMain(t)
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 62000}
	sa := &controlSA{peer: addressKey(peer), peerAddr: peer, natt: true, main: main, quick: make(map[uint32]*QuickModeResponder), quickUpdated: make(map[uint32]time.Time), responses: make(map[string][]byte), expires: time.Now().Add(time.Hour)}
	control := &ControlPlane{config: ControlPlaneConfig{Random: bytes.NewReader(bytes.Repeat([]byte{0x55}, 64))}, sas: map[Cookie]*controlSA{main.responderCookie: sa}}
	datagrams := control.Shutdown()
	if len(datagrams) != 1 || !datagrams[0].NATT || len(datagrams[0].Payload) == 0 || control.SACount() != 0 {
		t.Fatalf("datagrams=%#v SAs=%d", datagrams, control.SACount())
	}
	packet, err := DecodePacket(datagrams[0].Payload)
	if err != nil || packet.Exchange != ExchangeInformational || packet.Flags != FlagEncrypted {
		t.Fatalf("packet=%#v error=%v", packet, err)
	}
}

func TestControlPlaneProactiveDPDExpiresSilentPeer(t *testing.T) {
	main := testEstablishedMain(t)
	main.capabilities.DPD = true
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 500}
	now := time.Unix(100, 0)
	sa := &controlSA{peer: addressKey(peer), peerAddr: peer, main: main, quick: make(map[uint32]*QuickModeResponder), quickUpdated: make(map[uint32]time.Time), responses: make(map[string][]byte), expires: now.Add(time.Hour)}
	control := &ControlPlane{config: ControlPlaneConfig{Random: bytes.NewReader(bytes.Repeat([]byte{0x66}, 256)), DPDInterval: 20 * time.Second}, sas: map[Cookie]*controlSA{main.responderCookie: sa}}
	if got := control.PollDPD(now); len(got) != 0 {
		t.Fatalf("initial probes=%d", len(got))
	}
	probes := control.PollDPD(now.Add(20 * time.Second))
	if len(probes) != 1 {
		t.Fatalf("probes=%d", len(probes))
	}
	_, payloads, err := main.DecodeInformational(probes[0].Payload)
	if err != nil || payloads[0].(Notification).MessageType != NotifyRThere {
		t.Fatalf("payloads=%#v error=%v", payloads, err)
	}
	_ = control.PollDPD(now.Add(40 * time.Second))
	_ = control.PollDPD(now.Add(60 * time.Second))
	_ = control.PollDPD(now.Add(80 * time.Second))
	events := control.Maintain(now.Add(80 * time.Second))
	if control.SACount() != 0 || len(events) != 1 || events[0].Type != LifecycleExpireIKE {
		t.Fatalf("SAs=%d events=%#v", control.SACount(), events)
	}
}
