package esp

import (
	"encoding/binary"
	"fmt"
)

const (
	IPProtocolESP = 50
	IPProtocolUDP = 17
)

// SealIPv4Transport replaces an IPv4 packet's upper-layer payload with ESP
// while preserving its source, destination, options, DSCP, and fragmentation
// fields. Fragmentation must happen after ESP processing.
func SealIPv4Transport(ipv4 []byte, sa *SA) ([]byte, error) {
	headerLength, totalLength, err := ipv4Dimensions(ipv4)
	if err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(ipv4[6:8])&0x1fff != 0 {
		return nil, fmt.Errorf("%w: fragmented input", ErrInvalidPacket)
	}
	espWire, err := sa.Seal(ipv4[headerLength:totalLength], ipv4[9])
	if err != nil {
		return nil, err
	}
	if headerLength+len(espWire) > 65535 {
		return nil, fmt.Errorf("%w: IPv4 length", ErrInvalidPacket)
	}
	out := make([]byte, headerLength+len(espWire))
	copy(out, ipv4[:headerLength])
	copy(out[headerLength:], espWire)
	out[9] = IPProtocolESP
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	updateIPv4Checksum(out[:headerLength])
	return out, nil
}

// OpenIPv4Transport authenticates/decrypts ESP and restores the original
// upper-layer protocol and payload in the IPv4 packet.
func OpenIPv4Transport(ipv4 []byte, sa *SA) ([]byte, error) {
	headerLength, totalLength, err := ipv4Dimensions(ipv4)
	if err != nil {
		return nil, err
	}
	if ipv4[9] != IPProtocolESP {
		return nil, fmt.Errorf("%w: IPv4 protocol %d", ErrInvalidPacket, ipv4[9])
	}
	payload, next, err := sa.Open(ipv4[headerLength:totalLength])
	if err != nil {
		return nil, err
	}
	if headerLength+len(payload) > 65535 {
		return nil, ErrInvalidPacket
	}
	out := make([]byte, headerLength+len(payload))
	copy(out, ipv4[:headerLength])
	copy(out[headerLength:], payload)
	out[9] = next
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	updateIPv4Checksum(out[:headerLength])
	return out, nil
}

func ipv4Dimensions(packet []byte) (int, int, error) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0, 0, ErrShortPacket
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return 0, 0, ErrInvalidPacket
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < headerLength || total > len(packet) {
		return 0, 0, ErrInvalidPacket
	}
	return headerLength, total, nil
}

func updateIPv4Checksum(header []byte) {
	header[10], header[11] = 0, 0
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(header[10:12], ^uint16(sum))
}
