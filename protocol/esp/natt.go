package esp

import "bytes"

type NATTPacketType uint8

const (
	NATTInvalid NATTPacketType = iota
	NATTIKE
	NATTESP
	NATTKeepalive
)

var nonESPMarker = []byte{0, 0, 0, 0}

// ClassifyNATT implements RFC 3948 UDP/4500 demultiplexing.
func ClassifyNATT(datagram []byte) (NATTPacketType, []byte) {
	if len(datagram) == 1 && datagram[0] == 0xff {
		return NATTKeepalive, nil
	}
	if len(datagram) >= 4 && bytes.Equal(datagram[:4], nonESPMarker) {
		if len(datagram) == 4 {
			return NATTInvalid, nil
		}
		return NATTIKE, datagram[4:]
	}
	if len(datagram) >= HeaderSize {
		return NATTESP, datagram
	}
	return NATTInvalid, nil
}

func EncapsulateNATTIKE(ike []byte) []byte {
	return append(append([]byte(nil), nonESPMarker...), ike...)
}
func EncapsulateNATTESP(esp []byte) []byte { return append([]byte(nil), esp...) }
