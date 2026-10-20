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

	"github.com/eukhlg/ipsec-go/packetbuf"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
)

type Limits struct{ Packets, Bytes uint64 }
type SAConfig struct {
	// ReplayWindowSize is 64 by default, or a multiple of 64 up to 1024.
	ReplayWindowSize                 uint32
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
	replay, err := NewReplayWindow(config.ReplayWindowSize)
	if err != nil {
		return nil, err
	}
	return &SA{replay: replay, spi: config.SPI, block: block, authKey: append([]byte(nil), config.AuthenticationKey...), random: config.Random, limits: config.Limits, lifetime: config.Lifetime, created: config.Now(), now: config.Now}, nil
}

func (s *SA) SPI() uint32 { return s.spi }

// Seal preserves caller ownership. SealBuffer is the allocation-free payload path.
func (s *SA) Seal(payload []byte, nextHeader uint8) ([]byte, error) {
	b, err := packetbuf.Copy(payload)
	if err != nil {
		return nil, err
	}
	defer b.Release()
	if err = s.SealBuffer(b, nextHeader); err != nil {
		return nil, err
	}
	return append([]byte(nil), b.Bytes()...), nil
}

// SealBuffer pads, encrypts and authenticates exclusively owned storage in place.
// Ownership stays with the caller on both success and failure.
func (s *SA) SealBuffer(b *packetbuf.Buffer, nextHeader uint8) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sequence == ^uint32(0) {
		return ErrSequenceExhausted
	}
	size := b.Len()
	if err := s.checkLifetime(uint64(size)); err != nil {
		return err
	}
	blockSize := s.block.BlockSize()
	padLength := (blockSize - (size+2)%blockSize) % blockSize
	headerSize := HeaderSize + blockSize
	tailSize := padLength + 2 + ICVSizeHMACSHA196
	if size > packetbuf.MaxWire-headerSize-tailSize || b.Headroom() < headerSize || b.Tailroom() < tailSize {
		return packetbuf.ErrSize
	}
	// Generate before mutating the packet or consuming sequence/lifetime state.
	var randomIV [16]byte
	if _, err := io.ReadFull(s.random, randomIV[:blockSize]); err != nil {
		return err
	}
	header, _ := b.Prepend(headerSize)
	tail, _ := b.Append(tailSize)
	s.sequence++
	binary.BigEndian.PutUint32(header[:4], s.spi)
	binary.BigEndian.PutUint32(header[4:8], s.sequence)
	copy(header[HeaderSize:], randomIV[:blockSize])
	clear(randomIV[:])
	for i := 0; i < padLength; i++ {
		tail[i] = byte(i + 1)
	}
	tail[padLength], tail[padLength+1] = byte(padLength), nextHeader
	wire := b.Bytes()
	authEnd := len(wire) - ICVSizeHMACSHA196
	plain := wire[headerSize:authEnd]
	cipher.NewCBCEncrypter(s.block, header[HeaderSize:]).CryptBlocks(plain, plain)
	copy(wire[authEnd:], calculateICV(s.authKey, wire[:authEnd]))
	s.packets++
	s.bytes += uint64(size)
	return nil
}

// Open preserves caller-owned ciphertext; OpenInPlace explicitly permits mutation.
func (s *SA) Open(wire []byte) ([]byte, uint8, error) {
	owned := append([]byte(nil), wire...)
	payload, next, err := s.OpenInPlace(owned)
	if err != nil {
		clear(owned)
		return nil, 0, err
	}
	return payload, next, nil
}

// OpenInPlace authenticates before decrypting. The returned bounded view aliases
// wire and is valid only while its owner retains that storage. Failure may leave
// decrypted bytes in wire; the owner must clear storage before pooling it.
func (s *SA) OpenInPlace(wire []byte) ([]byte, uint8, error) {
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
	want := calculateICV(s.authKey, wire[:len(wire)-ICVSizeHMACSHA196])
	if subtle.ConstantTimeCompare(want, packet.ICV) != 1 {
		return nil, 0, ErrAuthentication
	}
	plain := packet.Ciphertext
	cipher.NewCBCDecrypter(s.block, packet.IV).CryptBlocks(plain, plain)
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
