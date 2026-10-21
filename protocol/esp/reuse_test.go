package esp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/eukhlg/ipsec-go/packetbuf"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
)

// Independent reference MACs catch retained packet data and cross-SA key reuse.
func TestRepeatedSAAuthentication(t *testing.T) {
	for _, keySize := range []int{16, 24, 32, 0} {
		t.Run(fmt.Sprint(keySize), func(t *testing.T) {
			var wg sync.WaitGroup
			for id := 1; id <= 8; id++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					c := testConfig(uint32(id))
					c.Random = nil
					c.AuthenticationKey = bytes.Repeat([]byte{byte(id)}, 20)
					if keySize == 0 {
						c.Transform.Encryption = isakmp.TransformESP3DES
						c.EncryptionKey = bytes.Repeat([]byte{byte(id)}, 24)
					} else {
						c.EncryptionKey = bytes.Repeat([]byte{byte(id)}, keySize)
					}
					out, err := NewSA(c)
					if err != nil {
						t.Error(err)
						return
					}
					in, err := NewSA(c)
					if err != nil {
						t.Error(err)
						return
					}
					for i := 0; i < 256; i++ {
						payload := bytes.Repeat([]byte{byte(i)}, i%73)
						var wire []byte
						if i%2 == 0 {
							wire, err = out.Seal(payload, 17)
						} else {
							b, _ := packetbuf.Copy(payload)
							err = out.SealBuffer(b, 17)
							wire = append([]byte(nil), b.Bytes()...)
							b.Release()
						}
						if err != nil {
							t.Error(err)
							return
						}
						end := len(wire) - ICVSizeHMACSHA196
						if !bytes.Equal(wire[end:], calculateICV(c.AuthenticationKey, wire[:end])) {
							t.Error("ICV differs from independent HMAC")
							return
						}
						bad := append([]byte(nil), wire...)
						bad[len(bad)-1] ^= 1
						saved := append([]byte(nil), bad...)
						if _, _, err = in.OpenInPlace(bad); !errors.Is(err, ErrAuthentication) || !bytes.Equal(bad, saved) {
							t.Errorf("authentication mutated ciphertext: %v", err)
							return
						}
						replay := append([]byte(nil), wire...)
						var got []byte
						var next uint8
						if i%2 == 0 {
							got, next, err = in.Open(wire)
						} else {
							got, next, err = in.OpenInPlace(wire)
						}
						if err != nil || next != 17 || !bytes.Equal(got, payload) {
							t.Errorf("round trip %d: %v", i, err)
							return
						}
						if _, _, err = in.OpenInPlace(replay); !errors.Is(err, ErrReplay) {
							t.Errorf("replay accepted: %v", err)
							return
						}
					}
				}(id)
			}
			wg.Wait()
		})
	}
}

func BenchmarkSAOwnedRoundTrip(b *testing.B) {
	c := testConfig(42)
	c.Random = nil
	out, _ := NewSA(c)
	in, _ := NewSA(c)
	payload := bytes.Repeat([]byte{0x42}, 1400)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buffer, _ := packetbuf.Copy(payload)
		if err := out.SealBuffer(buffer, 17); err != nil {
			buffer.Release()
			b.Fatal(err)
		}
		if _, _, err := in.OpenInPlace(buffer.Bytes()); err != nil {
			buffer.Release()
			b.Fatal(err)
		}
		buffer.Release()
	}
}

func calculateICV(key, wire []byte) []byte {
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(wire)
	return mac.Sum(nil)[:ICVSizeHMACSHA196]
}
