package isakmp

import (
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

var ErrUnsupportedTransform = errors.New("isakmp: unsupported transform")

// Phase1Transform is the normalized subset of an IKE phase 1 transform that
// this implementation can negotiate safely.
type Phase1Transform struct {
	Encryption      uint16
	Hash            uint16
	AuthMethod      uint16
	DHGroup         uint16
	KeyBits         int
	LifetimeSeconds uint32
}

type ESPTransform struct {
	Encryption     uint8
	Authentication uint16
	Encapsulation  uint16
	KeyBits        int
}

// ParseESPTransform validates an ESP transform for the L2TP/IPsec transport
// mode used by this server. NAT-T transport is accepted for later UDP/4500
// encapsulation support.
func ParseESPTransform(t Transform) (ESPTransform, error) {
	values := make(map[uint16]uint32)
	for _, attribute := range t.Attributes {
		if _, duplicate := values[attribute.Type]; duplicate {
			return ESPTransform{}, fmt.Errorf("%w: duplicate ESP attribute %d", ErrInvalidPayload, attribute.Type)
		}
		value, err := attributeUint32(attribute)
		if err != nil {
			return ESPTransform{}, err
		}
		values[attribute.Type] = value
	}
	for kind := range values {
		switch kind {
		case AttributeP2LifeType, AttributeP2LifeValue, AttributeP2DHGroup, AttributeP2Encapsulation, AttributeP2Authentication, AttributeP2KeyLength:
		default:
			return ESPTransform{}, fmt.Errorf("%w: ESP attribute %d", ErrUnsupportedTransform, kind)
		}
	}
	encapsulation, ok := values[AttributeP2Encapsulation]
	if !ok || (encapsulation != uint32(EncapsulationTransport) && encapsulation != uint32(EncapsulationNATTTransport)) {
		return ESPTransform{}, fmt.Errorf("%w: ESP encapsulation %d", ErrUnsupportedTransform, encapsulation)
	}
	authentication, ok := values[AttributeP2Authentication]
	if !ok || authentication != uint32(ESPAuthHMACSHA196) {
		return ESPTransform{}, fmt.Errorf("%w: ESP authentication %d", ErrUnsupportedTransform, authentication)
	}
	suite := ESPTransform{Encryption: t.ID, Authentication: uint16(authentication), Encapsulation: uint16(encapsulation), KeyBits: int(values[AttributeP2KeyLength])}
	switch suite.Encryption {
	case TransformESPAES:
		if suite.KeyBits != 128 && suite.KeyBits != 192 && suite.KeyBits != 256 {
			return ESPTransform{}, fmt.Errorf("%w: ESP AES key length %d", ErrUnsupportedTransform, suite.KeyBits)
		}
	case TransformESP3DES:
		if suite.KeyBits == 0 {
			suite.KeyBits = 192
		}
		if suite.KeyBits != 192 {
			return ESPTransform{}, fmt.Errorf("%w: ESP 3DES key length %d", ErrUnsupportedTransform, suite.KeyBits)
		}
	default:
		return ESPTransform{}, fmt.Errorf("%w: ESP encryption %d", ErrUnsupportedTransform, suite.Encryption)
	}
	return suite, nil
}

// ParsePhase1Transform validates and normalizes an IKE transform. The initial
// implementation intentionally supports the suites used by current L2TP/IPsec
// clients: AES-CBC or 3DES-CBC, HMAC-SHA1 or HMAC-SHA256, and PSK auth.
func ParsePhase1Transform(t Transform) (Phase1Transform, error) {
	if t.ID != TransformIKE {
		return Phase1Transform{}, fmt.Errorf("%w: transform id %d", ErrUnsupportedTransform, t.ID)
	}
	values := make(map[uint16]uint32)
	var lifetimeType uint32
	for _, attribute := range t.Attributes {
		value, err := attributeUint32(attribute)
		if err != nil {
			return Phase1Transform{}, err
		}
		if attribute.Type == AttributeP1LifeType {
			if lifetimeType != 0 {
				return Phase1Transform{}, fmt.Errorf("%w: consecutive lifetime types", ErrInvalidPayload)
			}
			lifetimeType = value
			continue
		}
		if attribute.Type == AttributeP1LifeValue {
			if lifetimeType == 0 {
				return Phase1Transform{}, fmt.Errorf("%w: lifetime value without type", ErrInvalidPayload)
			}
			if lifetimeType == uint32(LifeTypeSeconds) {
				values[AttributeP1LifeValue] = value
			}
			lifetimeType = 0
			continue
		}
		if _, duplicate := values[attribute.Type]; duplicate {
			return Phase1Transform{}, fmt.Errorf("%w: duplicate attribute %d", ErrInvalidPayload, attribute.Type)
		}
		values[attribute.Type] = value
	}
	if lifetimeType != 0 {
		return Phase1Transform{}, fmt.Errorf("%w: lifetime type without value", ErrInvalidPayload)
	}
	for _, required := range []uint16{AttributeP1Encryption, AttributeP1Hash, AttributeP1AuthMethod, AttributeP1DHGroup} {
		if _, ok := values[required]; !ok {
			return Phase1Transform{}, fmt.Errorf("%w: missing phase 1 attribute %d", ErrInvalidPayload, required)
		}
	}
	for kind := range values {
		switch kind {
		case AttributeP1Encryption, AttributeP1Hash, AttributeP1AuthMethod, AttributeP1DHGroup, AttributeP1KeyLength, AttributeP1LifeType, AttributeP1LifeValue:
		default:
			return Phase1Transform{}, fmt.Errorf("%w: attribute %d", ErrUnsupportedTransform, kind)
		}
	}
	suite := Phase1Transform{
		Encryption:      uint16(values[AttributeP1Encryption]),
		Hash:            uint16(values[AttributeP1Hash]),
		AuthMethod:      uint16(values[AttributeP1AuthMethod]),
		DHGroup:         uint16(values[AttributeP1DHGroup]),
		KeyBits:         int(values[AttributeP1KeyLength]),
		LifetimeSeconds: values[AttributeP1LifeValue],
	}
	if suite.AuthMethod != AuthPreSharedKey {
		return Phase1Transform{}, fmt.Errorf("%w: authentication method %d", ErrUnsupportedTransform, suite.AuthMethod)
	}
	if suite.DHGroup != DHGroup2 && suite.DHGroup != DHGroup14 {
		return Phase1Transform{}, fmt.Errorf("%w: DH group %d", ErrUnsupportedTransform, suite.DHGroup)
	}
	switch suite.Hash {
	case HashSHA1, HashSHA256:
	default:
		return Phase1Transform{}, fmt.Errorf("%w: hash %d", ErrUnsupportedTransform, suite.Hash)
	}
	switch suite.Encryption {
	case EncryptionAESCBC:
		if suite.KeyBits != 128 && suite.KeyBits != 192 && suite.KeyBits != 256 {
			return Phase1Transform{}, fmt.Errorf("%w: AES key length %d", ErrUnsupportedTransform, suite.KeyBits)
		}
	case Encryption3DESCBC:
		if suite.KeyBits == 0 {
			suite.KeyBits = 192
		}
		if suite.KeyBits != 192 {
			return Phase1Transform{}, fmt.Errorf("%w: 3DES key length %d", ErrUnsupportedTransform, suite.KeyBits)
		}
	default:
		return Phase1Transform{}, fmt.Errorf("%w: encryption %d", ErrUnsupportedTransform, suite.Encryption)
	}
	return suite, nil
}

func attributeUint32(attribute Attribute) (uint32, error) {
	if !attribute.Variable {
		return uint32(attribute.Value), nil
	}
	if len(attribute.Data) == 0 || len(attribute.Data) > 4 {
		return 0, fmt.Errorf("%w: attribute %d integer length", ErrInvalidPayload, attribute.Type)
	}
	var value uint32
	for _, b := range attribute.Data {
		value = value<<8 | uint32(b)
	}
	return value, nil
}

func (t Phase1Transform) hashFunc() (func() hash.Hash, error) {
	switch t.Hash {
	case HashSHA1:
		return sha1.New, nil
	case HashSHA256:
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("%w: hash %d", ErrUnsupportedTransform, t.Hash)
	}
}
