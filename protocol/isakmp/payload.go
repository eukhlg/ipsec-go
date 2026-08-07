package isakmp

import (
	"encoding/binary"
	"fmt"
)

type Payload interface {
	Type() PayloadType
	marshalBody() ([]byte, error)
}

type DataPayload struct {
	Kind PayloadType
	Data []byte
}

func (p DataPayload) Type() PayloadType { return p.Kind }
func (p DataPayload) marshalBody() ([]byte, error) {
	switch p.Kind {
	case PayloadKeyExchange, PayloadHash, PayloadSignature, PayloadNonce, PayloadVendorID, PayloadNATD, PayloadNATDDraft:
		return append([]byte(nil), p.Data...), nil
	default:
		return nil, fmt.Errorf("%w: type %d is not an opaque data payload", ErrInvalidPayload, p.Kind)
	}
}

type UnknownPayload struct {
	Kind PayloadType
	Data []byte
}

func (p UnknownPayload) Type() PayloadType { return p.Kind }
func (p UnknownPayload) marshalBody() ([]byte, error) {
	if p.Kind == PayloadNone {
		return nil, fmt.Errorf("%w: unknown payload type zero", ErrInvalidPayload)
	}
	return append([]byte(nil), p.Data...), nil
}

type Identification struct {
	IDType, ProtocolID uint8
	Port               uint16
	Data               []byte
}

func (Identification) Type() PayloadType { return PayloadIdentification }
func (p Identification) marshalBody() ([]byte, error) {
	out := make([]byte, 4+len(p.Data))
	out[0], out[1] = p.IDType, p.ProtocolID
	binary.BigEndian.PutUint16(out[2:4], p.Port)
	copy(out[4:], p.Data)
	return out, nil
}

type Certificate struct {
	Encoding uint8
	Data     []byte
}

func (Certificate) Type() PayloadType              { return PayloadCertificate }
func (p Certificate) marshalBody() ([]byte, error) { return append([]byte{p.Encoding}, p.Data...), nil }

type CertificateRequest struct {
	Encoding  uint8
	Authority []byte
}

func (CertificateRequest) Type() PayloadType { return PayloadCertificateReq }
func (p CertificateRequest) marshalBody() ([]byte, error) {
	return append([]byte{p.Encoding}, p.Authority...), nil
}

type Notification struct {
	DOI         uint32
	ProtocolID  uint8
	SPI         []byte
	MessageType uint16
	Data        []byte
}

func (Notification) Type() PayloadType { return PayloadNotification }
func (p Notification) marshalBody() ([]byte, error) {
	if len(p.SPI) > 255 {
		return nil, fmt.Errorf("%w: notification SPI too long", ErrInvalidPayload)
	}
	out := make([]byte, 8+len(p.SPI)+len(p.Data))
	binary.BigEndian.PutUint32(out[0:4], p.DOI)
	out[4], out[5] = p.ProtocolID, byte(len(p.SPI))
	binary.BigEndian.PutUint16(out[6:8], p.MessageType)
	copy(out[8:], p.SPI)
	copy(out[8+len(p.SPI):], p.Data)
	return out, nil
}

type Delete struct {
	DOI        uint32
	ProtocolID uint8
	SPIs       [][]byte
}

func (Delete) Type() PayloadType { return PayloadDelete }
func (p Delete) marshalBody() ([]byte, error) {
	if len(p.SPIs) == 0 || len(p.SPIs) > 65535 || len(p.SPIs[0]) == 0 || len(p.SPIs[0]) > 255 {
		return nil, fmt.Errorf("%w: invalid delete SPI collection", ErrInvalidPayload)
	}
	spiSize := len(p.SPIs[0])
	out := make([]byte, 8+spiSize*len(p.SPIs))
	binary.BigEndian.PutUint32(out[0:4], p.DOI)
	out[4], out[5] = p.ProtocolID, byte(spiSize)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(p.SPIs)))
	pos := 8
	for _, spi := range p.SPIs {
		if len(spi) != spiSize {
			return nil, fmt.Errorf("%w: inconsistent delete SPI sizes", ErrInvalidPayload)
		}
		copy(out[pos:], spi)
		pos += spiSize
	}
	return out, nil
}

type NATOriginalAddress struct {
	Kind    PayloadType
	IDType  uint8
	Address []byte
}

func (p NATOriginalAddress) Type() PayloadType { return p.Kind }
func (p NATOriginalAddress) marshalBody() ([]byte, error) {
	if p.Kind != PayloadNATOA && p.Kind != PayloadNATOADraft && p.Kind != PayloadNATOADraftAlt {
		return nil, fmt.Errorf("%w: invalid NAT-OA type", ErrInvalidPayload)
	}
	out := make([]byte, 4+len(p.Address))
	out[0] = p.IDType
	copy(out[4:], p.Address)
	return out, nil
}

func marshalPayloadChain(payloads []Payload) (PayloadType, []byte, error) {
	if len(payloads) == 0 {
		return PayloadNone, nil, nil
	}
	var out []byte
	for i, p := range payloads {
		if p == nil || p.Type() == PayloadNone {
			return 0, nil, fmt.Errorf("%w: nil or zero payload", ErrInvalidPayload)
		}
		body, err := p.marshalBody()
		if err != nil {
			return 0, nil, err
		}
		if len(body)+4 > maxPayloadSize {
			return 0, nil, fmt.Errorf("%w: payload too large", ErrInvalidPayload)
		}
		next := PayloadNone
		if i+1 < len(payloads) {
			next = payloads[i+1].Type()
		}
		start := len(out)
		out = append(out, byte(next), 0, 0, 0)
		binary.BigEndian.PutUint16(out[start+2:start+4], uint16(len(body)+4))
		out = append(out, body...)
	}
	return payloads[0].Type(), out, nil
}

func decodePayloadChain(first PayloadType, wire []byte) ([]Payload, error) {
	if first == PayloadNone {
		if len(wire) != 0 {
			return nil, fmt.Errorf("%w: trailing payload bytes", ErrInvalidPayload)
		}
		return nil, nil
	}
	payloads := make([]Payload, 0, 4)
	current := first
	for current != PayloadNone {
		if len(payloads) >= maxPayloads {
			return nil, fmt.Errorf("%w: too many payloads", ErrInvalidPayload)
		}
		if len(wire) < 4 {
			return nil, ErrShortPacket
		}
		next := PayloadType(wire[0])
		if wire[1] != 0 {
			return nil, fmt.Errorf("%w: nonzero reserved payload byte", ErrInvalidPayload)
		}
		size := int(binary.BigEndian.Uint16(wire[2:4]))
		if size < 4 || size > len(wire) {
			return nil, fmt.Errorf("%w: invalid payload length %d", ErrInvalidPayload, size)
		}
		p, err := decodePayload(current, wire[4:size])
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, p)
		wire = wire[size:]
		current = next
	}
	if len(wire) != 0 {
		return nil, fmt.Errorf("%w: trailing bytes after payload chain", ErrInvalidPayload)
	}
	return payloads, nil
}

func decodePayload(kind PayloadType, body []byte) (Payload, error) {
	switch kind {
	case PayloadSA:
		return decodeSA(body)
	case PayloadProposal, PayloadTransform:
		return nil, fmt.Errorf("%w: payload type %d is only valid inside an SA", ErrInvalidPayload, kind)
	case PayloadKeyExchange, PayloadHash, PayloadSignature, PayloadNonce, PayloadVendorID, PayloadNATD, PayloadNATDDraft:
		return DataPayload{Kind: kind, Data: append([]byte(nil), body...)}, nil
	case PayloadIdentification:
		if len(body) < 4 {
			return nil, ErrShortPacket
		}
		return Identification{IDType: body[0], ProtocolID: body[1], Port: binary.BigEndian.Uint16(body[2:4]), Data: append([]byte(nil), body[4:]...)}, nil
	case PayloadCertificate:
		if len(body) < 1 {
			return nil, ErrShortPacket
		}
		return Certificate{Encoding: body[0], Data: append([]byte(nil), body[1:]...)}, nil
	case PayloadCertificateReq:
		if len(body) < 1 {
			return nil, ErrShortPacket
		}
		return CertificateRequest{Encoding: body[0], Authority: append([]byte(nil), body[1:]...)}, nil
	case PayloadNotification:
		return decodeNotification(body)
	case PayloadDelete:
		return decodeDelete(body)
	case PayloadNATOA, PayloadNATOADraft, PayloadNATOADraftAlt:
		if len(body) < 4 {
			return nil, ErrShortPacket
		}
		if body[1] != 0 || body[2] != 0 || body[3] != 0 {
			return nil, fmt.Errorf("%w: NAT-OA reserved bytes", ErrInvalidPayload)
		}
		return NATOriginalAddress{Kind: kind, IDType: body[0], Address: append([]byte(nil), body[4:]...)}, nil
	default:
		return UnknownPayload{Kind: kind, Data: append([]byte(nil), body...)}, nil
	}
}

func decodeNotification(body []byte) (Payload, error) {
	if len(body) < 8 {
		return nil, ErrShortPacket
	}
	n := Notification{DOI: binary.BigEndian.Uint32(body[:4]), ProtocolID: body[4], MessageType: binary.BigEndian.Uint16(body[6:8])}
	spiSize := int(body[5])
	if len(body) < 8+spiSize {
		return nil, fmt.Errorf("%w: truncated notification SPI", ErrInvalidPayload)
	}
	n.SPI = append([]byte(nil), body[8:8+spiSize]...)
	n.Data = append([]byte(nil), body[8+spiSize:]...)
	return n, nil
}
func decodeDelete(body []byte) (Payload, error) {
	if len(body) < 8 {
		return nil, ErrShortPacket
	}
	d := Delete{DOI: binary.BigEndian.Uint32(body[:4]), ProtocolID: body[4]}
	size, count := int(body[5]), int(binary.BigEndian.Uint16(body[6:8]))
	if size == 0 || count == 0 || count > (len(body)-8)/size || 8+size*count != len(body) {
		return nil, fmt.Errorf("%w: invalid delete SPI dimensions", ErrInvalidPayload)
	}
	for pos := 8; pos < len(body); pos += size {
		d.SPIs = append(d.SPIs, append([]byte(nil), body[pos:pos+size]...))
	}
	return d, nil
}
