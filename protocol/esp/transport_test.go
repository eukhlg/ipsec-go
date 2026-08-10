package esp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func testIPv4(protocol byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], []byte{192, 0, 2, 1})
	copy(packet[16:20], []byte{198, 51, 100, 2})
	copy(packet[20:], payload)
	updateIPv4Checksum(packet[:20])
	return packet
}

func TestIPv4TransportRoundTrip(t *testing.T) {
	outbound, _ := NewSA(testConfig(0x12345678))
	inbound, _ := NewSA(testConfig(0x12345678))
	original := testIPv4(IPProtocolUDP, []byte("udp header and l2tp"))
	sealed, err := SealIPv4Transport(original, outbound)
	if err != nil {
		t.Fatal(err)
	}
	if sealed[9] != IPProtocolESP || bytes.Equal(sealed[20:], original[20:]) {
		t.Fatal("packet not transformed")
	}
	opened, err := OpenIPv4Transport(sealed, inbound)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, original) {
		t.Fatalf("opened=%x want=%x", opened, original)
	}
}

func TestNATTFraming(t *testing.T) {
	ike := []byte{1, 2, 3}
	kind, payload := ClassifyNATT(EncapsulateNATTIKE(ike))
	if kind != NATTIKE || !bytes.Equal(payload, ike) {
		t.Fatal("IKE classification")
	}
	esp := make([]byte, HeaderSize)
	esp[3] = 1
	kind, payload = ClassifyNATT(EncapsulateNATTESP(esp))
	if kind != NATTESP || !bytes.Equal(payload, esp) {
		t.Fatal("ESP classification")
	}
	if kind, _ = ClassifyNATT([]byte{0xff}); kind != NATTKeepalive {
		t.Fatal("keepalive")
	}
	if kind, _ = ClassifyNATT([]byte{1, 2}); kind != NATTInvalid {
		t.Fatal("invalid")
	}
}
