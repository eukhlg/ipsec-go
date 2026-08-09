package isakmp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

type QuickModeState uint8

const (
	QuickModeAwaitProposal QuickModeState = iota
	QuickModeAwaitConfirmation
	QuickModeEstablished
)

type QuickModeConfig struct {
	Transform                        Phase1Transform
	Secrets                          Phase1Secrets
	InitiatorCookie, ResponderCookie Cookie
	LastPhase1Block                  []byte
	Random                           io.Reader
	NonceSize                        int
}

type ESPDirectionalKeys struct {
	SPI                              uint32
	EncryptionKey, AuthenticationKey []byte
}
type ESPPair struct {
	Transform         ESPTransform
	Inbound, Outbound ESPDirectionalKeys
}

type QuickModeResponder struct {
	config                         QuickModeConfig
	state                          QuickModeState
	messageID                      uint32
	cipher                         *CBCContext
	initiatorNonce, responderNonce []byte
	pair                           ESPPair
}

func NewQuickModeResponder(config QuickModeConfig) (*QuickModeResponder, error) {
	if len(config.Secrets.SKEYIDa) == 0 || len(config.Secrets.SKEYIDd) == 0 || len(config.Secrets.Key) == 0 || len(config.LastPhase1Block) == 0 {
		return nil, ErrInvalidCryptoInput
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.NonceSize == 0 {
		config.NonceSize = 20
	}
	if config.NonceSize < 16 || config.NonceSize > 256 {
		return nil, ErrInvalidCryptoInput
	}
	return &QuickModeResponder{config: config}, nil
}

func (q *QuickModeResponder) State() QuickModeState { return q.state }
func (q *QuickModeResponder) Pair() (ESPPair, bool) {
	if q.state != QuickModeEstablished {
		return ESPPair{}, false
	}
	return clonePair(q.pair), true
}

func (q *QuickModeResponder) Handle(wire []byte) ([]byte, error) {
	packet, err := DecodePacket(wire)
	if err != nil {
		return nil, err
	}
	if packet.Exchange != ExchangeQuickMode || packet.Flags != FlagEncrypted || packet.MessageID == 0 || packet.InitiatorCookie != q.config.InitiatorCookie || packet.ResponderCookie != q.config.ResponderCookie {
		return nil, ErrUnexpectedExchange
	}
	if q.state == QuickModeAwaitProposal {
		q.messageID = packet.MessageID
		iv, err := Phase2IV(q.config.Transform, q.config.LastPhase1Block, q.messageID)
		if err != nil {
			return nil, err
		}
		q.cipher, err = NewCBCContext(q.config.Transform, q.config.Secrets.Key, iv)
		if err != nil {
			return nil, err
		}
		return q.handleProposal(packet)
	}
	if q.state == QuickModeAwaitConfirmation && packet.MessageID == q.messageID {
		return q.handleConfirmation(packet)
	}
	return nil, ErrUnexpectedExchange
}

func (q *QuickModeResponder) handleProposal(packet Packet) ([]byte, error) {
	plaintext, err := q.cipher.Decrypt(packet.EncryptedPayload)
	if err != nil {
		return nil, err
	}
	payloads, meaningful, err := decodePayloadsWithLength(packet.FirstPayload, plaintext)
	if err != nil || len(payloads) < 3 {
		return nil, ErrUnexpectedExchange
	}
	hashPayload, ok := payloads[0].(DataPayload)
	if !ok || hashPayload.Kind != PayloadHash {
		return nil, ErrUnexpectedExchange
	}
	hashPayloadLength := int(binary.BigEndian.Uint16(plaintext[2:4]))
	if !VerifyPRF(q.config.Transform.Hash, q.config.Secrets.SKEYIDa, hashPayload.Data, messageIDBytes(q.messageID), plaintext[hashPayloadLength:meaningful]) {
		return nil, fmt.Errorf("%w: HASH(1)", ErrInvalidCryptoInput)
	}
	sa, ok := payloads[1].(SecurityAssociation)
	if !ok {
		return nil, ErrUnexpectedExchange
	}
	nonce, ok := payloads[2].(DataPayload)
	if !ok || nonce.Kind != PayloadNonce || len(nonce.Data) < 16 {
		return nil, ErrUnexpectedExchange
	}
	selectedSA, espTransform, outboundSPI, inboundSPI, err := selectESPsa(sa, q.config.Random)
	if err != nil {
		return nil, err
	}
	q.initiatorNonce = append([]byte(nil), nonce.Data...)
	q.responderNonce = make([]byte, q.config.NonceSize)
	if _, err := io.ReadFull(q.config.Random, q.responderNonce); err != nil {
		return nil, err
	}
	// The initiator's offered SPI protects responder-to-initiator traffic;
	// the responder's selected SPI protects initiator-to-responder traffic.
	keySize := espTransform.KeyBits/8 + 20 // HMAC-SHA1 key material uses 20 bytes.
	outKeymat, err := DeriveESPKeyMaterial(q.config.Transform, q.config.Secrets.SKEYIDd, nil, ProtocolESP, uint32Bytes(outboundSPI), q.initiatorNonce, q.responderNonce, keySize)
	if err != nil {
		return nil, err
	}
	inKeymat, err := DeriveESPKeyMaterial(q.config.Transform, q.config.Secrets.SKEYIDd, nil, ProtocolESP, uint32Bytes(inboundSPI), q.initiatorNonce, q.responderNonce, keySize)
	if err != nil {
		return nil, err
	}
	q.pair = ESPPair{Transform: espTransform,
		Inbound:  ESPDirectionalKeys{SPI: inboundSPI, EncryptionKey: append([]byte(nil), inKeymat[:espTransform.KeyBits/8]...), AuthenticationKey: append([]byte(nil), inKeymat[espTransform.KeyBits/8:]...)},
		Outbound: ESPDirectionalKeys{SPI: outboundSPI, EncryptionKey: append([]byte(nil), outKeymat[:espTransform.KeyBits/8]...), AuthenticationKey: append([]byte(nil), outKeymat[espTransform.KeyBits/8:]...)},
	}
	after := []Payload{selectedSA, DataPayload{Kind: PayloadNonce, Data: q.responderNonce}}
	_, afterWire, err := MarshalPayloads(after)
	if err != nil {
		return nil, err
	}
	hash2, err := QuickModeHash2(q.config.Transform, q.config.Secrets.SKEYIDa, q.messageID, q.initiatorNonce, afterWire)
	if err != nil {
		return nil, err
	}
	first, body, err := MarshalPayloads(append([]Payload{DataPayload{Kind: PayloadHash, Data: hash2}}, after...))
	if err != nil {
		return nil, err
	}
	q.state = QuickModeAwaitConfirmation
	return (Packet{InitiatorCookie: q.config.InitiatorCookie, ResponderCookie: q.config.ResponderCookie, Exchange: ExchangeQuickMode, Flags: FlagEncrypted, MessageID: q.messageID, FirstPayload: first, EncryptedPayload: q.cipher.Encrypt(body)}).MarshalBinary()
}

func (q *QuickModeResponder) handleConfirmation(packet Packet) ([]byte, error) {
	plaintext, err := q.cipher.Decrypt(packet.EncryptedPayload)
	if err != nil {
		return nil, err
	}
	payloads, _, err := decodePayloadsWithLength(packet.FirstPayload, plaintext)
	if err != nil || len(payloads) != 1 {
		return nil, ErrUnexpectedExchange
	}
	hashPayload, ok := payloads[0].(DataPayload)
	if !ok || hashPayload.Kind != PayloadHash {
		return nil, ErrUnexpectedExchange
	}
	expected, err := QuickModeHash3(q.config.Transform, q.config.Secrets.SKEYIDa, q.messageID, q.initiatorNonce, q.responderNonce)
	if err != nil || !VerifyPRFValue(expected, hashPayload.Data) {
		return nil, fmt.Errorf("%w: HASH(3)", ErrInvalidCryptoInput)
	}
	q.state = QuickModeEstablished
	return nil, nil
}

func selectESPsa(sa SecurityAssociation, random io.Reader) (SecurityAssociation, ESPTransform, uint32, uint32, error) {
	for _, proposal := range sa.Proposals {
		if proposal.ProtocolID != ProtocolESP || len(proposal.SPI) != 4 {
			continue
		}
		for _, candidate := range proposal.Transforms {
			transform, err := ParseESPTransform(candidate)
			if err != nil {
				continue
			}
			spiBytes := make([]byte, 4)
			if _, err := io.ReadFull(random, spiBytes); err != nil {
				return SecurityAssociation{}, ESPTransform{}, 0, 0, err
			}
			spi := binary.BigEndian.Uint32(spiBytes)
			if spi == 0 {
				spi, spiBytes[3] = 1, 1
			}
			selected := SecurityAssociation{DOI: sa.DOI, Situation: sa.Situation, Proposals: []Proposal{{Number: proposal.Number, ProtocolID: ProtocolESP, SPI: spiBytes, Transforms: []Transform{candidate}}}}
			return selected, transform, binary.BigEndian.Uint32(proposal.SPI), spi, nil
		}
	}
	return SecurityAssociation{}, ESPTransform{}, 0, 0, ErrUnsupportedTransform
}

func decodePayloadsWithLength(first PayloadType, plaintext []byte) ([]Payload, int, error) {
	current, offset := first, 0
	for current != PayloadNone {
		if offset+4 > len(plaintext) {
			return nil, 0, ErrInvalidPayload
		}
		size := int(binary.BigEndian.Uint16(plaintext[offset+2 : offset+4]))
		if size < 4 || offset+size > len(plaintext) {
			return nil, 0, ErrInvalidPayload
		}
		current, offset = PayloadType(plaintext[offset]), offset+size
	}
	payloads, err := DecodePayloads(first, plaintext)
	return payloads, offset, err
}

func messageIDBytes(id uint32) []byte { return uint32Bytes(id) }
func uint32Bytes(value uint32) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], value)
	return out[:]
}
func clonePair(p ESPPair) ESPPair {
	p.Inbound.EncryptionKey = append([]byte(nil), p.Inbound.EncryptionKey...)
	p.Inbound.AuthenticationKey = append([]byte(nil), p.Inbound.AuthenticationKey...)
	p.Outbound.EncryptionKey = append([]byte(nil), p.Outbound.EncryptionKey...)
	p.Outbound.AuthenticationKey = append([]byte(nil), p.Outbound.AuthenticationKey...)
	return p
}
