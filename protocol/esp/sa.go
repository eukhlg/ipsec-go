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
	"hash"
	"io"
	"sync"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	"github.com/eukhlg/netio/packetbuf"
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

// Standard-library AES and 3DES CBC modes expose SetIV for independent packets.
// Keep separate directions because CryptBlocks advances the mode's chaining IV.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

type SA struct {
	cryptoPool     sync.Pool
	sealPool       sync.Pool
	mu             sync.Mutex
	spi            uint32
	block          cipher.Block
	decrypt        cbcMode
	sealIV         [aes.BlockSize]byte
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
	var iv [aes.BlockSize]byte
	decrypt := cipher.NewCBCDecrypter(block, iv[:block.BlockSize()]).(cbcMode)
	s := &SA{decrypt: decrypt, replay: replay, spi: config.SPI, block: block, random: config.Random, limits: config.Limits, lifetime: config.Lifetime, created: config.Now(), now: config.Now}
	authKey := append([]byte(nil), config.AuthenticationKey...)
	s.cryptoPool.New = func() any {
		return &receiveCrypto{mac: hmac.New(sha1.New, authKey), decrypt: cipher.NewCBCDecrypter(block, make([]byte, block.BlockSize())).(cbcMode)}
	}
	s.sealPool.New = func() any {
		return &sealCrypto{mac: hmac.New(sha1.New, authKey), encrypt: cipher.NewCBCEncrypter(block, make([]byte, block.BlockSize())).(cbcMode)}
	}
	return s, nil
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
	p, err := s.ReserveSeal(b, nextHeader)
	if err != nil {
		return err
	}
	p.Seal()
	return nil
}

// SealPacket is an outbound packet whose sequence number, IV, padding and
// headers are already fixed. Seal encrypts and authenticates it; it may run on
// any goroutine, concurrently with other packets of the same SA, because each
// call uses its own keyed state. The buffer must not change until Seal returns.
type SealPacket struct {
	sa         *SA
	wire       []byte
	headerSize int
}

type sealCrypto struct {
	mac     hash.Hash
	encrypt cbcMode
	icv     [sha1.Size]byte
}

// ReserveSeal does the ordered part of sealing under the SA lock: it checks the
// sequence space and lifetime, generates the IV, assigns the next sequence
// number and writes headers and padding. Callers that seal in parallel must
// send packets in reservation order, or within the peer's replay window.
// Ownership stays with the caller on both success and failure.
func (s *SA) ReserveSeal(b *packetbuf.Buffer, nextHeader uint8) (SealPacket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sequence == ^uint32(0) {
		return SealPacket{}, ErrSequenceExhausted
	}
	size := b.Len()
	if err := s.checkLifetime(uint64(size)); err != nil {
		return SealPacket{}, err
	}
	blockSize := s.block.BlockSize()
	padLength := (blockSize - (size+2)%blockSize) % blockSize
	headerSize := HeaderSize + blockSize
	tailSize := padLength + 2 + ICVSizeHMACSHA196
	if size > packetbuf.MaxWire-headerSize-tailSize || b.Headroom() < headerSize || b.Tailroom() < tailSize {
		return SealPacket{}, packetbuf.ErrSize
	}
	// Generate before mutating the packet or consuming sequence/lifetime state.
	if _, err := io.ReadFull(s.random, s.sealIV[:blockSize]); err != nil {
		clear(s.sealIV[:])
		return SealPacket{}, err
	}
	header, _ := b.Prepend(headerSize)
	tail, _ := b.Append(tailSize)
	s.sequence++
	binary.BigEndian.PutUint32(header[:4], s.spi)
	binary.BigEndian.PutUint32(header[4:8], s.sequence)
	copy(header[HeaderSize:], s.sealIV[:blockSize])
	clear(s.sealIV[:])
	for i := 0; i < padLength; i++ {
		tail[i] = byte(i + 1)
	}
	tail[padLength], tail[padLength+1] = byte(padLength), nextHeader
	s.packets++
	s.bytes += uint64(size)
	return SealPacket{sa: s, wire: b.Bytes(), headerSize: headerSize}, nil
}

// Seal encrypts and authenticates the reserved packet in place.
func (p SealPacket) Seal() {
	c := p.sa.sealPool.Get().(*sealCrypto)
	defer p.sa.sealPool.Put(c)
	authEnd := len(p.wire) - ICVSizeHMACSHA196
	plain := p.wire[p.headerSize:authEnd]
	c.encrypt.SetIV(p.wire[HeaderSize:p.headerSize])
	c.encrypt.CryptBlocks(plain, plain)
	c.mac.Reset()
	_, _ = c.mac.Write(p.wire[:authEnd])
	copy(p.wire[authEnd:], c.mac.Sum(c.icv[:0])[:ICVSizeHMACSHA196])
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
	p, err := s.Precheck(wire)
	if err != nil {
		return nil, 0, err
	}
	p.Authenticate()
	return p.Commit()
}

type receiveCrypto struct {
	mac     hash.Hash
	decrypt cbcMode
	icv     [sha1.Size]byte
}

// ReceivePacket borrows wire through Commit. One owner calls Authenticate once,
// then Commit once; callers may process different packets concurrently. Commit
// ordering is the caller's responsibility. No replay state changes before Commit.
type ReceivePacket struct {
	sa            *SA
	packet        Packet
	wire, payload []byte
	next          uint8
	err           error
	authenticated bool
}

// Precheck decodes and checks replay eligibility without changing the window.
func (s *SA) Precheck(wire []byte) (*ReceivePacket, error) {
	packet, err := DecodePacketView(wire, s.block.BlockSize(), ICVSizeHMACSHA196)
	if err != nil {
		return nil, err
	}
	if packet.SPI != s.spi {
		return nil, ErrInvalidPacket
	}
	s.mu.Lock()
	err = s.replay.Check(packet.Sequence)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &ReceivePacket{sa: s, packet: packet, wire: wire}, nil
}

// Authenticate checks the constant-time ICV before any in-place decryption.
// Keyed state belongs exclusively to this invocation, including within one SA.
func (p *ReceivePacket) Authenticate() {
	c := p.sa.cryptoPool.Get().(*receiveCrypto)
	defer p.sa.cryptoPool.Put(c)
	c.mac.Reset()
	_, _ = c.mac.Write(p.wire[:len(p.wire)-ICVSizeHMACSHA196])
	want := c.mac.Sum(c.icv[:0])[:ICVSizeHMACSHA196]
	if subtle.ConstantTimeCompare(want, p.packet.ICV) != 1 {
		p.err = ErrAuthentication
		return
	}
	p.authenticated = true
	plain := p.packet.Ciphertext
	c.decrypt.SetIV(p.packet.IV)
	c.decrypt.CryptBlocks(plain, plain)
	padLength := int(plain[len(plain)-2])
	if padLength+2 > len(plain) {
		p.err = ErrInvalidPacket
		return
	}
	padStart := len(plain) - 2 - padLength
	for i := 0; i < padLength; i++ {
		if plain[padStart+i] != byte(i+1) {
			p.err = ErrInvalidPacket
			return
		}
	}
	p.payload = plain[:padStart:padStart]
	p.next = plain[len(plain)-1]
}

// Commit rechecks replay and lifetime under the SA lock. Authentication and
// padding failures never consume sequence numbers or lifetime accounting.
func (p *ReceivePacket) Commit() ([]byte, uint8, error) {
	s := p.sa
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.replay.Check(p.packet.Sequence); err != nil {
		return nil, 0, err
	}
	if p.err != nil {
		return nil, 0, p.err
	}
	if !p.authenticated {
		return nil, 0, ErrAuthentication
	}
	if err := s.checkLifetime(uint64(len(p.payload))); err != nil {
		return nil, 0, err
	}
	if err := s.replay.Accept(p.packet.Sequence); err != nil {
		return nil, 0, err
	}
	s.packets++
	s.bytes += uint64(len(p.payload))
	return p.payload, p.next, nil
}

func (s *SA) checkLifetime(nextBytes uint64) error {
	if s.lifetime > 0 {
		if age := s.now().Sub(s.created); age >= s.lifetime {
			return s.lifetimeError(LifetimeTime, 0, age)
		}
	}
	if s.limits.Packets != 0 && s.packets >= s.limits.Packets {
		return s.lifetimeError(LifetimePackets, s.limits.Packets, 0)
	}
	if s.limits.Bytes != 0 && (nextBytes > s.limits.Bytes || s.bytes > s.limits.Bytes-nextBytes) {
		return s.lifetimeError(LifetimeBytes, s.limits.Bytes, 0)
	}
	return nil
}

// lifetimeError is only reached once per exhausted SA in practice, so the
// allocation is off the per-packet path. Callers hold s.mu.
func (s *SA) lifetimeError(reason LifetimeReason, limit uint64, age time.Duration) error {
	return &LifetimeError{SPI: s.spi, Reason: reason, Packets: s.packets, Bytes: s.bytes, Limit: limit, Lifetime: s.lifetime, Age: age}
}
