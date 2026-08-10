package esp

import "testing"

func FuzzDecodePacket(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 52))
	f.Fuzz(func(t *testing.T, wire []byte) {
		packet, err := DecodePacket(wire, 16, 12)
		if err != nil {
			return
		}
		encoded, err := packet.MarshalBinary(16, 12)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodePacket(encoded, 16, 12); err != nil {
			t.Fatal(err)
		}
	})
}
