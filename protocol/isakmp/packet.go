package isakmp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	headerSize     = 28
	maxPacketSize  = 65535
	maxPayloads    = 64
	maxPayloadSize = 65535
)

var (
	ErrShortPacket    = errors.New("isakmp: packet is too short")
	ErrInvalidPacket  = errors.New("isakmp: invalid packet")
	ErrBadVersion     = errors.New("isakmp: unsupported version")
	ErrInvalidPayload = errors.New("isakmp: invalid payload")
)

type Cookie [8]byte

type Packet struct {
	InitiatorCookie Cookie
	ResponderCookie Cookie
	Version         uint8
	Exchange        ExchangeType
	Flags           Flags
	MessageID       uint32
	Payloads        []Payload

	// FirstPayload and EncryptedPayload preserve an encrypted body until the
	// IKE crypto layer can decrypt it. They are only used with FlagEncrypted.
	FirstPayload     PayloadType
	EncryptedPayload []byte
}

func (p Packet) MarshalBinary() ([]byte, error) {
	version := p.Version
	if version == 0 {
		version = VersionIKEv1
	}
	if version != VersionIKEv1 {
		return nil, ErrBadVersion
	}
	if p.Flags & ^Flags(FlagEncrypted|FlagCommit|FlagAuthenticationOnly) != 0 {
		return nil, fmt.Errorf("%w: reserved flag bits", ErrInvalidPacket)
	}
	var first PayloadType
	var body []byte
	if p.Flags&FlagEncrypted != 0 {
		if len(p.Payloads) != 0 || p.FirstPayload == PayloadNone || len(p.EncryptedPayload) == 0 {
			return nil, fmt.Errorf("%w: encrypted packet requires opaque body and first payload", ErrInvalidPacket)
		}
		first = p.FirstPayload
		body = append([]byte(nil), p.EncryptedPayload...)
	} else {
		if len(p.EncryptedPayload) != 0 || len(p.Payloads) > maxPayloads {
			return nil, fmt.Errorf("%w: invalid cleartext payload collection", ErrInvalidPacket)
		}
		var err error
		first, body, err = marshalPayloadChain(p.Payloads)
		if err != nil {
			return nil, err
		}
	}
	if headerSize+len(body) > maxPacketSize {
		return nil, fmt.Errorf("%w: packet too large", ErrInvalidPacket)
	}
	out := make([]byte, headerSize+len(body))
	copy(out[0:8], p.InitiatorCookie[:])
	copy(out[8:16], p.ResponderCookie[:])
	out[16], out[17], out[18], out[19] = byte(first), version, byte(p.Exchange), byte(p.Flags)
	binary.BigEndian.PutUint32(out[20:24], p.MessageID)
	binary.BigEndian.PutUint32(out[24:28], uint32(len(out)))
	copy(out[28:], body)
	return out, nil
}

func DecodePacket(wire []byte) (Packet, error) {
	if len(wire) < headerSize {
		return Packet{}, ErrShortPacket
	}
	declared := binary.BigEndian.Uint32(wire[24:28])
	if declared < headerSize || declared > maxPacketSize || int(declared) != len(wire) {
		return Packet{}, fmt.Errorf("%w: declared length %d, datagram length %d", ErrInvalidPacket, declared, len(wire))
	}
	if wire[17] != VersionIKEv1 {
		return Packet{}, ErrBadVersion
	}
	flags := Flags(wire[19])
	if flags & ^Flags(FlagEncrypted|FlagCommit|FlagAuthenticationOnly) != 0 {
		return Packet{}, fmt.Errorf("%w: reserved flag bits", ErrInvalidPacket)
	}
	p := Packet{Version: wire[17], Exchange: ExchangeType(wire[18]), Flags: flags, MessageID: binary.BigEndian.Uint32(wire[20:24])}
	copy(p.InitiatorCookie[:], wire[0:8])
	copy(p.ResponderCookie[:], wire[8:16])
	first := PayloadType(wire[16])
	body := wire[headerSize:]
	if flags&FlagEncrypted != 0 {
		if first == PayloadNone || len(body) == 0 {
			return Packet{}, fmt.Errorf("%w: empty encrypted body", ErrInvalidPacket)
		}
		p.FirstPayload = first
		p.EncryptedPayload = append([]byte(nil), body...)
		return p, nil
	}
	if first == PayloadNone && len(body) != 0 {
		return Packet{}, fmt.Errorf("%w: body without first payload", ErrInvalidPacket)
	}
	var err error
	p.Payloads, err = decodePayloadChain(first, body)
	if err != nil {
		return Packet{}, err
	}
	return p, nil
}
