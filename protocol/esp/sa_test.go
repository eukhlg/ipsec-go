package esp

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/isakmp"
)

func testConfig(spi uint32) SAConfig {
	return SAConfig{SPI: spi, Transform: isakmp.ESPTransform{Encryption: isakmp.TransformESPAES, Authentication: isakmp.ESPAuthHMACSHA196, Encapsulation: isakmp.EncapsulationTransport, KeyBits: 128}, EncryptionKey: bytes.Repeat([]byte{0x11}, 16), AuthenticationKey: bytes.Repeat([]byte{0x22}, 20), Random: bytes.NewReader(bytes.Repeat([]byte{0x33}, 1024))}
}

func TestSARoundTripPaddingAndSequence(t *testing.T) {
	outbound, err := NewSA(testConfig(0x01020304))
	if err != nil {
		t.Fatal(err)
	}
	inbound, _ := NewSA(testConfig(0x01020304))
	for i, payload := range [][]byte{[]byte("short"), bytes.Repeat([]byte{0x44}, 30)} {
		wire, err := outbound.Seal(payload, 17)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := DecodePacket(wire, 16, 12)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Sequence != uint32(i+1) || len(packet.IV) != 16 || len(packet.ICV) != 12 {
			t.Fatalf("packet=%#v", packet)
		}
		got, next, err := inbound.Open(wire)
		if err != nil || next != 17 || !bytes.Equal(got, payload) {
			t.Fatalf("got=%x next=%d err=%v", got, next, err)
		}
	}
}

func TestAESCBCRFC3602TransportVector(t *testing.T) {
	decode := func(value string) []byte {
		out, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	key := decode("90d382b410eeba7ad938c46cec1a82bf")
	iv := decode("e96e8c08ab465763fd098d45dd3ff893")
	payload := decode("08000ebda70a00008e9c083db95b070008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	want := decode("0000432100000001e96e8c08ab465763fd098d45dd3ff893f663c25d325c18c6a9453e194e120849a4870b66cc6b9965330013b4898dc856a4699e523a55db080b59ec3a8e4b7e52775b07d1db34ed9c538ab50c551b874aa269add047ad2d5913ac19b7cfbad4a6")
	config := testConfig(0x4321)
	config.EncryptionKey = key
	config.Random = bytes.NewReader(iv)
	sa, err := NewSA(config)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sa.Seal(payload, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[:len(wire)-ICVSizeHMACSHA196], want) {
		t.Fatalf("wire=%x", wire[:len(wire)-ICVSizeHMACSHA196])
	}
}

func TestSARejectsTamperReplayAndWrongSPI(t *testing.T) {
	outbound, _ := NewSA(testConfig(7))
	inbound, _ := NewSA(testConfig(7))
	wire, _ := outbound.Seal([]byte("payload"), 17)
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := inbound.Open(tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper error=%v", err)
	}
	if _, _, err := inbound.Open(wire); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inbound.Open(wire); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error=%v", err)
	}
	wrong, _ := NewSA(testConfig(8))
	if _, _, err := wrong.Open(wire); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("SPI error=%v", err)
	}
}

func TestSARejectsPaddingBeforeAdvancingReplay(t *testing.T) {
	config := testConfig(9)
	outbound, _ := NewSA(config)
	inbound, _ := NewSA(config)
	wire, _ := outbound.Seal([]byte("payload"), 17)
	// Re-encrypting malformed padding while retaining a valid ICV is tested by
	// using the package-private fields, ensuring validation precedes Accept.
	packet, _ := DecodePacket(wire, 16, 12)
	plain := make([]byte, len(packet.Ciphertext))
	cipher.NewCBCDecrypter(outbound.block, packet.IV).CryptBlocks(plain, packet.Ciphertext)
	plain[len(plain)-3] = 0xff
	cipher.NewCBCEncrypter(outbound.block, packet.IV).CryptBlocks(packet.Ciphertext, plain)
	bad, _ := packet.MarshalBinary(16, 12)
	copy(bad[len(bad)-12:], calculateICV(config.AuthenticationKey, bad[:len(bad)-12]))
	if _, _, err := inbound.Open(bad); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("padding error=%v", err)
	}
	if _, _, err := inbound.Open(wire); err != nil {
		t.Fatalf("sequence consumed after invalid padding: %v", err)
	}
}

func TestSALimits(t *testing.T) {
	config := testConfig(10)
	config.Limits = Limits{Packets: 1}
	sa, _ := NewSA(config)
	if _, err := sa.Seal([]byte{1}, 17); err != nil {
		t.Fatal(err)
	}
	if _, err := sa.Seal([]byte{2}, 17); !errors.Is(err, ErrSALifetime) {
		t.Fatalf("error=%v", err)
	}
}

func TestSATimeLifetime(t *testing.T) {
	now := time.Unix(1, 0)
	config := testConfig(11)
	config.Lifetime = time.Minute
	config.Now = func() time.Time { return now }
	sa, _ := NewSA(config)
	if _, err := sa.Seal([]byte{1}, 17); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := sa.Seal([]byte{2}, 17); !errors.Is(err, ErrSALifetime) {
		t.Fatalf("error=%v", err)
	}
}

func TestReplayWindowOutOfOrder(t *testing.T) {
	var window ReplayWindow
	for _, seq := range []uint32{5, 3, 4, 70, 69} {
		if err := window.Accept(seq); err != nil {
			t.Fatalf("seq=%d err=%v", seq, err)
		}
	}
	for _, seq := range []uint32{5, 3, 1, 70} {
		if err := window.Check(seq); !errors.Is(err, ErrReplay) {
			t.Fatalf("seq=%d err=%v", seq, err)
		}
	}
}
