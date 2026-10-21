package esp

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	"math/rand"
	"testing"
	"time"
)

func (s *SA) legacyOpenInPlace(wire []byte) ([]byte, uint8, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	packet, err := DecodePacketView(wire, s.block.BlockSize(), ICVSizeHMACSHA196)
	if err != nil {
		return nil, 0, err
	}
	if packet.SPI != s.spi {
		return nil, 0, ErrInvalidPacket
	}
	if err = s.replay.Check(packet.Sequence); err != nil {
		return nil, 0, err
	}
	want := s.calculateICV(wire[:len(wire)-ICVSizeHMACSHA196])
	if subtle.ConstantTimeCompare(want, packet.ICV) != 1 {
		return nil, 0, ErrAuthentication
	}
	plain := packet.Ciphertext
	s.decrypt.SetIV(packet.IV)
	s.decrypt.CryptBlocks(plain, plain)
	padLength := int(plain[len(plain)-2])
	if padLength+2 > len(plain) {
		return nil, 0, ErrInvalidPacket
	}
	padStart := len(plain) - 2 - padLength
	for i := 0; i < padLength; i++ {
		if plain[padStart+i] != byte(i+1) {
			return nil, 0, ErrInvalidPacket
		}
	}
	payload := plain[:padStart:padStart]
	next := plain[len(plain)-1]
	if err = s.checkLifetime(uint64(len(payload))); err != nil {
		return nil, 0, err
	}
	if err = s.replay.Accept(packet.Sequence); err != nil {
		return nil, 0, err
	}
	s.packets++
	s.bytes += uint64(len(payload))
	return payload, next, nil
}

func TestPhasedLegacyEquivalence(t *testing.T) {
	for _, size := range []int{16, 24, 32, 0} {
		for _, edge := range []string{"none", "packets", "bytes", "time"} {
			t.Run(fmt.Sprintf("%d/%s", size, edge), func(t *testing.T) {
				c := testConfig(123)
				c.Random = nil
				if size == 0 {
					c.Transform.Encryption = isakmp.TransformESP3DES
					c.EncryptionKey = bytes.Repeat([]byte{7}, 24)
				} else {
					c.EncryptionKey = bytes.Repeat([]byte{7}, size)
				}
				out, _ := NewSA(c)
				wires := make([][]byte, 2500)
				for i := range wires {
					var err error
					wires[i], err = out.Seal(bytes.Repeat([]byte{byte(i)}, i%80), 17)
					if err != nil {
						t.Fatal(err)
					}
				}
				now := time.Unix(1, 0)
				c.Now = func() time.Time { return now }
				c.ReplayWindowSize = 1024
				switch edge {
				case "packets":
					c.Limits.Packets = 700
				case "bytes":
					c.Limits.Bytes = 27000
				case "time":
					c.Lifetime = time.Second
				}
				a, _ := NewSA(c)
				b, _ := NewSA(c)
				rng := rand.New(rand.NewSource(99))
				for i := 0; i < 4000; i++ {
					index := rng.Intn(len(wires))
					if i < 1100 {
						index = i
					}
					w1 := append([]byte(nil), wires[index]...)
					if rng.Intn(5) == 0 {
						w1[len(w1)-1] ^= 1
					}
					w2 := append([]byte(nil), w1...)
					if i == 1200 {
						now = now.Add(time.Second)
					}
					p1, n1, e1 := a.OpenInPlace(w1)
					p2, n2, e2 := b.legacyOpenInPlace(w2)
					if e1 != e2 || n1 != n2 || !bytes.Equal(p1, p2) || !bytes.Equal(w1, w2) || a.packets != b.packets || a.bytes != b.bytes {
						t.Fatalf("iteration %d: phased=%v legacy=%v", i, e1, e2)
					}
				}
			})
		}
	}
}
