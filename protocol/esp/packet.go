// Package esp implements the IPsec ESP wire format and transport-mode SAs.
package esp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	HeaderSize        = 8
	ICVSizeHMACSHA196 = 12
)

var (
	ErrShortPacket       = errors.New("esp: packet is too short")
	ErrInvalidPacket     = errors.New("esp: invalid packet")
	ErrAuthentication    = errors.New("esp: authentication failed")
	ErrReplay            = errors.New("esp: replayed or stale sequence")
	ErrSequenceExhausted = errors.New("esp: sequence space exhausted")
	ErrSALifetime        = errors.New("esp: security association lifetime exceeded")
)

// LifetimeReason identifies which negotiated security association limit was reached.
type LifetimeReason uint8

const (
	LifetimeTime LifetimeReason = iota + 1
	LifetimePackets
	LifetimeBytes
)

func (r LifetimeReason) String() string {
	switch r {
	case LifetimeTime:
		return "time"
	case LifetimePackets:
		return "packets"
	case LifetimeBytes:
		return "bytes"
	default:
		return "unknown"
	}
}

// LifetimeError reports an exhausted security association limit. It matches
// ErrSALifetime with errors.Is, so existing callers keep working unchanged.
// Packets and Bytes are the counters before the rejected packet. Limit is the
// packet or byte limit (zero for time); Age is set for time expiry.
type LifetimeError struct {
	SPI            uint32
	Reason         LifetimeReason
	Packets, Bytes uint64
	Limit          uint64
	Lifetime, Age  time.Duration
}

func (e *LifetimeError) Error() string {
	switch e.Reason {
	case LifetimeTime:
		return fmt.Sprintf("%v: spi=%08x reason=time age=%s lifetime=%s", ErrSALifetime, e.SPI, e.Age, e.Lifetime)
	default:
		return fmt.Sprintf("%v: spi=%08x reason=%s packets=%d bytes=%d limit=%d", ErrSALifetime, e.SPI, e.Reason, e.Packets, e.Bytes, e.Limit)
	}
}

func (e *LifetimeError) Is(target error) bool { return target == ErrSALifetime }

type Packet struct {
	SPI        uint32
	Sequence   uint32
	IV         []byte
	Ciphertext []byte
	ICV        []byte
}

func DecodePacket(wire []byte, blockSize, icvSize int) (Packet, error) {
	p, err := DecodePacketView(wire, blockSize, icvSize)
	if err != nil {
		return Packet{}, err
	}
	p.IV = append([]byte(nil), p.IV...)
	p.Ciphertext = append([]byte(nil), p.Ciphertext...)
	p.ICV = append([]byte(nil), p.ICV...)
	return p, nil
}

// DecodePacketView returns bounded borrowed slices, valid for the wire lifetime.
func DecodePacketView(wire []byte, blockSize, icvSize int) (Packet, error) {
	if blockSize <= 0 || blockSize > 16 || icvSize <= 0 || icvSize > 64 || len(wire) < HeaderSize+blockSize+blockSize+icvSize {
		return Packet{}, ErrShortPacket
	}
	payloadEnd := len(wire) - icvSize
	if (payloadEnd-HeaderSize-blockSize)%blockSize != 0 {
		return Packet{}, fmt.Errorf("%w: encrypted payload alignment", ErrInvalidPacket)
	}
	p := Packet{SPI: binary.BigEndian.Uint32(wire[:4]), Sequence: binary.BigEndian.Uint32(wire[4:8])}
	if p.SPI == 0 || p.Sequence == 0 {
		return Packet{}, fmt.Errorf("%w: zero SPI or sequence", ErrInvalidPacket)
	}
	p.IV = wire[HeaderSize : HeaderSize+blockSize : HeaderSize+blockSize]
	p.Ciphertext = wire[HeaderSize+blockSize : payloadEnd : payloadEnd]
	p.ICV = wire[payloadEnd:len(wire):len(wire)]
	return p, nil
}

func (p Packet) MarshalBinary(blockSize, icvSize int) ([]byte, error) {
	if p.SPI == 0 || p.Sequence == 0 || len(p.IV) != blockSize || len(p.Ciphertext) == 0 || len(p.Ciphertext)%blockSize != 0 || len(p.ICV) != icvSize {
		return nil, ErrInvalidPacket
	}
	out := make([]byte, HeaderSize+len(p.IV)+len(p.Ciphertext)+len(p.ICV))
	binary.BigEndian.PutUint32(out[:4], p.SPI)
	binary.BigEndian.PutUint32(out[4:8], p.Sequence)
	copy(out[8:], p.IV)
	copy(out[8+len(p.IV):], p.Ciphertext)
	copy(out[len(out)-len(p.ICV):], p.ICV)
	return out, nil
}
