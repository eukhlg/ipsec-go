package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/isakmp"
)

type Limits struct{ Packets, Bytes uint64 }
type SAConfig struct {
	SPI                              uint32
	Transform                        isakmp.ESPTransform
	EncryptionKey, AuthenticationKey []byte
	Random                           io.Reader
	Limits                           Limits
	Lifetime                         time.Duration
	Now                              func() time.Time
}

type SA struct {
	mu             sync.Mutex
	spi            uint32
	block          cipher.Block
	authKey        []byte
	random         io.Reader
	sequence       uint32
	replay         ReplayWindow
	packets, bytes uint64
	limits         Limits
	lifetime       time.Duration
	created        time.Time
	now            func() time.Time
}

func NewSA(config SAConfig) (*SA, error) {
	if config.SPI == 0 || len(config.AuthenticationKey) == 0 || config.Transform.Authentication != isakmp.ESPAuthHMACSHA196 {
		return nil, ErrInvalidPacket
	}
	var block cipher.Block
	var err error
	switch config.Transform.Encryption {
	case isakmp.TransformESPAES:
		block, err = aes.NewCipher(config.EncryptionKey)
	case isakmp.TransformESP3DES:
		block, err = des.NewTripleDESCipher(config.EncryptionKey)
	default:
		return nil, fmt.Errorf("%w: transform %d", ErrInvalidPacket, config.Transform.Encryption)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPacket, err)
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &SA{spi: config.SPI, block: block, authKey: append([]byte(nil), config.AuthenticationKey...), random: config.Random, limits: config.Limits, lifetime: config.Lifetime, created: config.Now(), now: config.Now}, nil
}

func (s *SA) SPI() uint32 { return s.spi }

func (s *SA) Seal(payload []byte, nextHeader uint8) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sequence == ^uint32(0) {
		return nil, ErrSequenceExhausted
	}
	if err := s.checkLifetime(uint64(len(payload))); err != nil {
		return nil, err
	}
	s.sequence++
	padLength := s.block.BlockSize() - (len(payload)+2)%s.block.BlockSize()
	if padLength == s.block.BlockSize() {
		padLength = 0
	}
	// Assemble the entire packet in its owned output buffer. The payload region
	// starts as padded plaintext and is encrypted in place before authentication.
	plainLength := len(payload) + padLength + 2
	ivEnd := HeaderSize + s.block.BlockSize()
	authEnd := ivEnd + plainLength
	wire := make([]byte, authEnd+ICVSizeHMACSHA196)
	binary.BigEndian.PutUint32(wire[:4], s.spi)
	binary.BigEndian.PutUint32(wire[4:8], s.sequence)
	iv := wire[HeaderSize:ivEnd]
	if _, err := io.ReadFull(s.random, iv); err != nil {
		s.sequence--
		return nil, err
	}
	plain := wire[ivEnd:authEnd]
	copy(plain, payload)
	for i := 0; i < padLength; i++ {
		plain[len(payload)+i] = byte(i + 1)
	}
	plain[len(plain)-2], plain[len(plain)-1] = byte(padLength), nextHeader
	cipher.NewCBCEncrypter(s.block, iv).CryptBlocks(plain, plain)
	copy(wire[authEnd:], calculateICV(s.authKey, wire[:authEnd]))
	s.packets++
	s.bytes += uint64(len(payload))
	return wire, nil
}

func (s *SA) Open(wire []byte) ([]byte, uint8, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	packet, err := DecodePacket(wire, s.block.BlockSize(), ICVSizeHMACSHA196)
	if err != nil {
		return nil, 0, err
	}
	if packet.SPI != s.spi {
		return nil, 0, ErrInvalidPacket
	}
	if err := s.replay.Check(packet.Sequence); err != nil {
		return nil, 0, err
	}
	want := calculateICV(s.authKey, wire[:len(wire)-ICVSizeHMACSHA196])
	if subtle.ConstantTimeCompare(want, packet.ICV) != 1 {
		return nil, 0, ErrAuthentication
	}
	plain := make([]byte, len(packet.Ciphertext))
	cipher.NewCBCDecrypter(s.block, packet.IV).CryptBlocks(plain, packet.Ciphertext)
	if len(plain) < 2 {
		return nil, 0, ErrInvalidPacket
	}
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
	payload := append([]byte(nil), plain[:padStart]...)
	next := plain[len(plain)-1]
	if err := s.checkLifetime(uint64(len(payload))); err != nil {
		return nil, 0, err
	}
	if err := s.replay.Accept(packet.Sequence); err != nil {
		return nil, 0, err
	}
	s.packets++
	s.bytes += uint64(len(payload))
	return payload, next, nil
}

func (s *SA) checkLifetime(nextBytes uint64) error {
	if s.lifetime > 0 && s.now().Sub(s.created) >= s.lifetime {
		return ErrSALifetime
	}
	if s.limits.Packets != 0 && s.packets >= s.limits.Packets {
		return ErrSALifetime
	}
	if s.limits.Bytes != 0 && (nextBytes > s.limits.Bytes || s.bytes > s.limits.Bytes-nextBytes) {
		return ErrSALifetime
	}
	return nil
}

func calculateICV(key, wire []byte) []byte {
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(wire)
	return mac.Sum(nil)[:ICVSizeHMACSHA196]
}
