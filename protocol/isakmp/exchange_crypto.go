package isakmp

import (
	"encoding/binary"
)

// MarshalPayloads exposes the exact payload bytes used by IKE authentication
// hashes and encrypted bodies. The returned first type belongs in the header.
func MarshalPayloads(payloads []Payload) (PayloadType, []byte, error) {
	return marshalPayloadChain(payloads)
}

// DecodePayloads decodes a decrypted payload body. Once the payload chain is
// complete, trailing bytes are CBC padding and may contain any value (RFC 2408).
func DecodePayloads(first PayloadType, plaintext []byte) ([]Payload, error) {
	payloads := make([]Payload, 0, 4)
	current := first
	wire := plaintext
	for current != PayloadNone {
		if len(payloads) >= maxPayloads || len(wire) < 4 {
			return nil, ErrInvalidPayload
		}
		next := PayloadType(wire[0])
		if wire[1] != 0 {
			return nil, ErrInvalidPayload
		}
		size := int(binary.BigEndian.Uint16(wire[2:4]))
		if size < 4 || size > len(wire) {
			return nil, ErrInvalidPayload
		}
		payload, err := decodePayload(current, wire[4:size])
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, payload)
		wire, current = wire[size:], next
	}
	return payloads, nil
}

// MainModeHash calculates HASH_I or HASH_R. initiatorSA and identityBody must
// contain payload bodies only; ISAKMP generic payload headers are not included.
func MainModeHash(transform Phase1Transform, skeyid, initiatorPublic, responderPublic []byte, initiatorCookie, responderCookie Cookie, initiatorSA, identityBody []byte, initiator bool) ([]byte, error) {
	if initiator {
		return PRF(transform.Hash, skeyid, initiatorPublic, responderPublic, initiatorCookie[:], responderCookie[:], initiatorSA, identityBody)
	}
	return PRF(transform.Hash, skeyid, responderPublic, initiatorPublic, responderCookie[:], initiatorCookie[:], initiatorSA, identityBody)
}

func QuickModeHash1(transform Phase1Transform, skeyidA []byte, messageID uint32, payloadsAfterHash []byte) ([]byte, error) {
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], messageID)
	return PRF(transform.Hash, skeyidA, id[:], payloadsAfterHash)
}

func QuickModeHash2(transform Phase1Transform, skeyidA []byte, messageID uint32, initiatorNonce, payloadsAfterHash []byte) ([]byte, error) {
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], messageID)
	return PRF(transform.Hash, skeyidA, id[:], initiatorNonce, payloadsAfterHash)
}

func QuickModeHash3(transform Phase1Transform, skeyidA []byte, messageID uint32, initiatorNonce, responderNonce []byte) ([]byte, error) {
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], messageID)
	return PRF(transform.Hash, skeyidA, []byte{0}, id[:], initiatorNonce, responderNonce)
}

func DeriveESPKeyMaterial(transform Phase1Transform, skeyidD, quickDH []byte, protocol uint8, spi, initiatorNonce, responderNonce []byte, size int) ([]byte, error) {
	if len(skeyidD) == 0 || len(spi) == 0 || len(initiatorNonce) == 0 || len(responderNonce) == 0 || size <= 0 {
		return nil, ErrInvalidCryptoInput
	}
	base := make([][]byte, 0, 5)
	if len(quickDH) != 0 {
		base = append(base, quickDH)
	}
	base = append(base, []byte{protocol}, spi, initiatorNonce, responderNonce)
	var out, previous []byte
	for len(out) < size {
		parts := base
		if len(previous) != 0 {
			parts = append([][]byte{previous}, base...)
		}
		block, err := PRF(transform.Hash, skeyidD, parts...)
		if err != nil {
			return nil, err
		}
		out, previous = append(out, block...), block
	}
	return out[:size], nil
}

func Phase2IV(transform Phase1Transform, lastPhase1Block []byte, messageID uint32) ([]byte, error) {
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], messageID)
	hashFunc, err := transform.hashFunc()
	if err != nil {
		return nil, err
	}
	blockSize, err := transform.blockSize()
	if err != nil {
		return nil, err
	}
	h := hashFunc()
	_, _ = h.Write(lastPhase1Block)
	_, _ = h.Write(id[:])
	sum := h.Sum(nil)
	return append([]byte(nil), sum[:blockSize]...), nil
}
