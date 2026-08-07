package isakmp

import (
	"encoding/binary"
	"fmt"
)

const (
	maxProposals  = 32
	maxTransforms = 64
	maxAttributes = 64
)

type SecurityAssociation struct {
	DOI, Situation uint32
	Proposals      []Proposal
}

func (SecurityAssociation) Type() PayloadType { return PayloadSA }
func (s SecurityAssociation) marshalBody() ([]byte, error) {
	if len(s.Proposals) == 0 || len(s.Proposals) > maxProposals {
		return nil, fmt.Errorf("%w: invalid proposal count", ErrInvalidPayload)
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[:4], s.DOI)
	binary.BigEndian.PutUint32(out[4:8], s.Situation)
	for i, p := range s.Proposals {
		body, err := p.marshalBody()
		if err != nil {
			return nil, err
		}
		if len(body)+4 > maxPayloadSize {
			return nil, fmt.Errorf("%w: proposal too large", ErrInvalidPayload)
		}
		next := PayloadNone
		if i+1 < len(s.Proposals) {
			next = PayloadProposal
		}
		start := len(out)
		out = append(out, byte(next), 0, 0, 0)
		binary.BigEndian.PutUint16(out[start+2:start+4], uint16(len(body)+4))
		out = append(out, body...)
	}
	return out, nil
}

type Proposal struct {
	Number, ProtocolID uint8
	SPI                []byte
	Transforms         []Transform
}

func (p Proposal) marshalBody() ([]byte, error) {
	if len(p.SPI) > 255 || len(p.Transforms) == 0 || len(p.Transforms) > maxTransforms {
		return nil, fmt.Errorf("%w: invalid proposal", ErrInvalidPayload)
	}
	out := make([]byte, 4+len(p.SPI))
	out[0], out[1], out[2], out[3] = p.Number, p.ProtocolID, byte(len(p.SPI)), byte(len(p.Transforms))
	copy(out[4:], p.SPI)
	for i, t := range p.Transforms {
		body, err := t.marshalBody()
		if err != nil {
			return nil, err
		}
		if len(body)+4 > maxPayloadSize {
			return nil, fmt.Errorf("%w: transform too large", ErrInvalidPayload)
		}
		next := PayloadNone
		if i+1 < len(p.Transforms) {
			next = PayloadTransform
		}
		start := len(out)
		out = append(out, byte(next), 0, 0, 0)
		binary.BigEndian.PutUint16(out[start+2:start+4], uint16(len(body)+4))
		out = append(out, body...)
	}
	return out, nil
}

type Transform struct {
	Number, ID uint8
	Attributes []Attribute
}

func (t Transform) marshalBody() ([]byte, error) {
	if len(t.Attributes) > maxAttributes {
		return nil, fmt.Errorf("%w: too many transform attributes", ErrInvalidPayload)
	}
	out := []byte{t.Number, t.ID, 0, 0}
	for _, a := range t.Attributes {
		wire, err := a.marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, wire...)
	}
	return out, nil
}

type Attribute struct {
	Type     uint16
	Value    uint16
	Data     []byte
	Variable bool
}

func TVAttribute(kind, value uint16) Attribute { return Attribute{Type: kind, Value: value} }
func TLVAttribute(kind uint16, data []byte) Attribute {
	return Attribute{Type: kind, Data: append([]byte(nil), data...), Variable: true}
}
func (a Attribute) marshal() ([]byte, error) {
	if a.Type == 0 || a.Type > 0x7fff {
		return nil, fmt.Errorf("%w: invalid attribute type", ErrInvalidPayload)
	}
	if !a.Variable {
		out := make([]byte, 4)
		binary.BigEndian.PutUint16(out[:2], a.Type|0x8000)
		binary.BigEndian.PutUint16(out[2:], a.Value)
		return out, nil
	}
	if len(a.Data) > 65535 {
		return nil, fmt.Errorf("%w: attribute too large", ErrInvalidPayload)
	}
	out := make([]byte, 4+len(a.Data))
	binary.BigEndian.PutUint16(out[:2], a.Type)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(a.Data)))
	copy(out[4:], a.Data)
	return out, nil
}

func decodeSA(body []byte) (Payload, error) {
	if len(body) < 8 {
		return nil, ErrShortPacket
	}
	s := SecurityAssociation{DOI: binary.BigEndian.Uint32(body[:4]), Situation: binary.BigEndian.Uint32(body[4:8])}
	wire := body[8:]
	for {
		if len(s.Proposals) >= maxProposals {
			return nil, fmt.Errorf("%w: too many proposals", ErrInvalidPayload)
		}
		next, part, rest, err := splitNested(PayloadProposal, wire)
		if err != nil {
			return nil, err
		}
		p, err := decodeProposal(part)
		if err != nil {
			return nil, err
		}
		s.Proposals = append(s.Proposals, p)
		wire = rest
		if next == PayloadNone {
			break
		}
		if next != PayloadProposal {
			return nil, fmt.Errorf("%w: proposal chain points to %d", ErrInvalidPayload, next)
		}
	}
	if len(wire) != 0 {
		return nil, fmt.Errorf("%w: trailing SA bytes", ErrInvalidPayload)
	}
	return s, nil
}

func decodeProposal(body []byte) (Proposal, error) {
	if len(body) < 4 {
		return Proposal{}, ErrShortPacket
	}
	p := Proposal{Number: body[0], ProtocolID: body[1]}
	spiSize, count := int(body[2]), int(body[3])
	if count == 0 || count > maxTransforms || len(body) < 4+spiSize {
		return Proposal{}, fmt.Errorf("%w: invalid proposal dimensions", ErrInvalidPayload)
	}
	p.SPI = append([]byte(nil), body[4:4+spiSize]...)
	wire := body[4+spiSize:]
	for len(p.Transforms) < count {
		next, part, rest, err := splitNested(PayloadTransform, wire)
		if err != nil {
			return Proposal{}, err
		}
		t, err := decodeTransform(part)
		if err != nil {
			return Proposal{}, err
		}
		p.Transforms = append(p.Transforms, t)
		wire = rest
		if len(p.Transforms) < count && next != PayloadTransform {
			return Proposal{}, fmt.Errorf("%w: short transform chain", ErrInvalidPayload)
		}
		if len(p.Transforms) == count && next != PayloadNone {
			return Proposal{}, fmt.Errorf("%w: transform count mismatch", ErrInvalidPayload)
		}
	}
	if len(wire) != 0 {
		return Proposal{}, fmt.Errorf("%w: trailing proposal bytes", ErrInvalidPayload)
	}
	return p, nil
}

func decodeTransform(body []byte) (Transform, error) {
	if len(body) < 4 {
		return Transform{}, ErrShortPacket
	}
	if body[2] != 0 || body[3] != 0 {
		return Transform{}, fmt.Errorf("%w: transform reserved bytes", ErrInvalidPayload)
	}
	t := Transform{Number: body[0], ID: body[1]}
	wire := body[4:]
	for len(wire) > 0 {
		if len(t.Attributes) >= maxAttributes {
			return Transform{}, fmt.Errorf("%w: too many attributes", ErrInvalidPayload)
		}
		if len(wire) < 4 {
			return Transform{}, ErrShortPacket
		}
		rawType := binary.BigEndian.Uint16(wire[:2])
		a := Attribute{Type: rawType & 0x7fff}
		if a.Type == 0 {
			return Transform{}, fmt.Errorf("%w: zero attribute type", ErrInvalidPayload)
		}
		if rawType&0x8000 != 0 {
			a.Value = binary.BigEndian.Uint16(wire[2:4])
			wire = wire[4:]
		} else {
			size := int(binary.BigEndian.Uint16(wire[2:4]))
			if len(wire) < 4+size {
				return Transform{}, fmt.Errorf("%w: truncated attribute", ErrInvalidPayload)
			}
			a.Variable = true
			a.Data = append([]byte(nil), wire[4:4+size]...)
			wire = wire[4+size:]
		}
		t.Attributes = append(t.Attributes, a)
	}
	return t, nil
}

func splitNested(expected PayloadType, wire []byte) (PayloadType, []byte, []byte, error) {
	if len(wire) < 4 {
		return 0, nil, nil, ErrShortPacket
	}
	if wire[1] != 0 {
		return 0, nil, nil, fmt.Errorf("%w: nested reserved byte", ErrInvalidPayload)
	}
	size := int(binary.BigEndian.Uint16(wire[2:4]))
	if size < 4 || size > len(wire) {
		return 0, nil, nil, fmt.Errorf("%w: invalid nested payload length", ErrInvalidPayload)
	}
	if expected == PayloadNone {
		return 0, nil, nil, fmt.Errorf("%w: invalid nested type", ErrInvalidPayload)
	}
	return PayloadType(wire[0]), wire[4:size], wire[size:], nil
}
