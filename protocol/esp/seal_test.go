package esp

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/eukhlg/ipsec-go/protocol/isakmp"
)

func TestSealBufferOwnershipAndPadding(t *testing.T) {
	for _, transform := range []struct {
		name       string
		encryption uint8
		keyBytes   int
	}{
		{"AES128", isakmp.TransformESPAES, 16},
		{"AES192", isakmp.TransformESPAES, 24},
		{"AES256", isakmp.TransformESPAES, 32},
		{"3DES", isakmp.TransformESP3DES, 24},
	} {
		t.Run(transform.name, func(t *testing.T) {
			config := testConfig(42)
			config.Transform.Encryption = transform.encryption
			config.EncryptionKey = bytes.Repeat([]byte{0x11}, transform.keyBytes)
			outbound, err := NewSA(config)
			if err != nil {
				t.Fatal(err)
			}
			inbound, err := NewSA(config)
			if err != nil {
				t.Fatal(err)
			}
			var previous, saved []byte
			for size := 0; size <= 2*outbound.block.BlockSize(); size++ {
				payload := bytes.Repeat([]byte{0x44}, size)
				original := append([]byte(nil), payload...)
				wire, err := outbound.Seal(payload, 17)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(payload, original) || !bytes.Equal(previous, saved) {
					t.Fatal("Seal modified caller-owned data")
				}
				packet, err := DecodePacket(wire, outbound.block.BlockSize(), ICVSizeHMACSHA196)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(packet.ICV, calculateICV(config.AuthenticationKey, wire[:len(wire)-ICVSizeHMACSHA196])) {
					t.Fatal("invalid ICV")
				}
				plain := make([]byte, len(packet.Ciphertext))
				cipher.NewCBCDecrypter(outbound.block, packet.IV).CryptBlocks(plain, packet.Ciphertext)
				padding := (outbound.block.BlockSize() - (size+2)%outbound.block.BlockSize()) % outbound.block.BlockSize()
				if len(plain) != size+padding+2 || plain[len(plain)-2] != byte(padding) {
					t.Fatalf("size %d: invalid padding length", size)
				}
				for i := 0; i < padding; i++ {
					if plain[size+i] != byte(i+1) {
						t.Fatal("invalid padding")
					}
				}
				got, next, err := inbound.Open(wire)
				if err != nil || next != 17 || !bytes.Equal(got, original) {
					t.Fatalf("size %d: next=%d err=%v", size, next, err)
				}
				previous, saved = wire, append([]byte(nil), wire...)
				for i := range payload {
					payload[i] ^= 0xff
				}
				if !bytes.Equal(wire, saved) {
					t.Fatal("output aliases payload")
				}
			}
		})
	}
}

func TestSealRandomFailurePreservesState(t *testing.T) {
	config := testConfig(42)
	config.Random = bytes.NewReader([]byte{1, 2, 3})
	config.Limits = Limits{Packets: 1, Bytes: 7}
	sa, err := NewSA(config)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sa.Seal([]byte("payload"), 17)
	if !errors.Is(err, io.ErrUnexpectedEOF) || wire != nil {
		t.Fatalf("wire=%x err=%v", wire, err)
	}
	if sa.sequence != 0 || sa.packets != 0 || sa.bytes != 0 {
		t.Fatal("failed seal consumed SA state")
	}
	sa.random = bytes.NewReader(bytes.Repeat([]byte{0x33}, 16))
	wire, err = sa.Seal([]byte("payload"), 17)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := DecodePacket(wire, 16, 12)
	if err != nil || packet.Sequence != 1 {
		t.Fatalf("sequence=%d err=%v", packet.Sequence, err)
	}
	if _, err := sa.Seal(nil, 17); !errors.Is(err, ErrSALifetime) {
		t.Fatalf("limit error=%v", err)
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, size := range []int{64, 1400} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			config := testConfig(42)
			config.Random = nil // Use real per-packet crypto/rand IVs, as in production.
			sa, err := NewSA(config)
			if err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := sa.Seal(payload, 17); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
