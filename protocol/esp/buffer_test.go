package esp

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	"github.com/eukhlg/netio/packetbuf"
	"testing"
)

func TestOwnedRoundTripBoundaries(t *testing.T) {
	for _, keySize := range []int{16, 24, 32, 0} {
		config := testConfig(42)
		config.Random = nil
		if keySize == 0 {
			config.Transform.Encryption = isakmp.TransformESP3DES
			keySize = 24
		}
		config.EncryptionKey = bytes.Repeat([]byte{0x11}, keySize)
		out, _ := NewSA(config)
		in, _ := NewSA(config)
		sizes := []int{0, 1, 6, 7, 8, 13, 14, 15, 16, 17, 30, 31, 32, 1400, 65450}
		for _, size := range sizes {
			payload := bytes.Repeat([]byte{0x44}, size)
			buffer, _ := packetbuf.Copy(payload)
			if err := out.SealBuffer(buffer, 17); err != nil {
				buffer.Release()
				t.Fatalf("size %d: %v", size, err)
			}
			wire := buffer.Bytes()
			saved := append([]byte(nil), wire...)
			view, next, err := in.OpenInPlace(wire)
			if err != nil || next != 17 || !bytes.Equal(view, payload) {
				buffer.Release()
				t.Fatalf("size=%d next=%d err=%v", size, next, err)
			}
			if cap(view) != len(view) {
				t.Fatal("unbounded inner view")
			}
			if size > 0 && &view[0] != &wire[HeaderSize+out.block.BlockSize()] {
				t.Fatal("payload copied")
			}
			if _, _, err = in.OpenInPlace(saved); !errors.Is(err, ErrReplay) {
				t.Fatalf("replay: %v", err)
			}
			buffer.Release()
		}

		bs := out.block.BlockSize()
		cipherRoom := packetbuf.MaxWire - HeaderSize - bs - ICVSizeHMACSHA196
		maxPayload := cipherRoom - cipherRoom%bs - 2
		for _, size := range []int{maxPayload - 1, maxPayload, maxPayload + 1} {
			b, _ := packetbuf.Acquire(size)
			before := out.sequence
			err := out.SealBuffer(b, 17)
			if size <= maxPayload && err != nil {
				t.Fatalf("maximum payload %d: %v", size, err)
			}
			if size > maxPayload && (!errors.Is(err, packetbuf.ErrSize) || out.sequence != before) {
				t.Fatal("maximum padding overflow accepted or consumed sequence")
			}
			b.Release()
		}
		oversize, _ := packetbuf.Acquire(packetbuf.MaxPacket)
		before := out.sequence
		if err := out.SealBuffer(oversize, 17); !errors.Is(err, packetbuf.ErrSize) {
			t.Fatalf("oversize: %v", err)
		}
		if out.sequence != before {
			t.Fatal("oversize consumed sequence")
		}
		oversize.Release()
	}
}

func TestInPlaceFailuresPreserveAuthenticationAndReplay(t *testing.T) {
	config := testConfig(9)
	out, _ := NewSA(config)
	in, _ := NewSA(config)
	valid, _ := out.Seal([]byte("payload"), 17)
	for n := 0; n < len(valid); n++ {
		if _, _, err := in.OpenInPlace(append([]byte(nil), valid[:n]...)); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	bad := append([]byte(nil), valid...)
	bad[len(bad)-1] ^= 1
	saved := append([]byte(nil), bad...)
	if _, _, err := in.OpenInPlace(bad); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	if !bytes.Equal(bad, saved) {
		t.Fatal("decrypted unauthenticated input")
	}
	bad = append([]byte(nil), valid...)
	packet, _ := DecodePacketView(bad, 16, 12)
	cipher.NewCBCDecrypter(out.block, packet.IV).CryptBlocks(packet.Ciphertext, packet.Ciphertext)
	packet.Ciphertext[len(packet.Ciphertext)-2] = 255
	cipher.NewCBCEncrypter(out.block, packet.IV).CryptBlocks(packet.Ciphertext, packet.Ciphertext)
	copy(packet.ICV, calculateICV(config.AuthenticationKey, bad[:len(bad)-12]))
	if _, _, err := in.OpenInPlace(bad); !errors.Is(err, ErrInvalidPacket) {
		t.Fatal(err)
	}
	original := append([]byte(nil), valid...)
	if _, _, err := in.Open(valid); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(valid, original) {
		t.Fatal("legacy Open changed caller storage")
	}
	if in.packets != 1 || in.bytes != 7 {
		t.Fatal("failure advanced accounting")
	}
}

func TestOwnedIVsAndRandomFailure(t *testing.T) {
	c := testConfig(42)
	c.Random = nil
	s, _ := NewSA(c)
	a, _ := packetbuf.Copy([]byte("hello"))
	b, _ := packetbuf.Copy([]byte("hello"))
	defer a.Release()
	defer b.Release()
	if err := s.SealBuffer(a, 17); err != nil {
		t.Fatal(err)
	}
	if err := s.SealBuffer(b, 17); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Bytes()[8:24], b.Bytes()[8:24]) {
		t.Fatal("repeated random IV")
	}
	c.Random = bytes.NewReader(nil)
	s, _ = NewSA(c)
	p, _ := packetbuf.Copy([]byte("hello"))
	defer p.Release()
	if err := s.SealBuffer(p, 17); err == nil {
		t.Fatal("missing random error")
	}
	if string(p.Bytes()) != "hello" || s.sequence != 0 || s.packets != 0 {
		t.Fatal("random failure changed packet or SA")
	}
}
