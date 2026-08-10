package isakmp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

type QuickModeState uint8

const (
	QuickModeAwaitProposal QuickModeState = iota
	QuickModeAwaitConfirmation
	QuickModeEstablished
	QuickModeFailed
)

type QuickModeConfig struct {
	Transform                        Phase1Transform
	Secrets                          Phase1Secrets
	InitiatorCookie, ResponderCookie Cookie
	LastPhase1Block                  []byte
	Random                           io.Reader
	NonceSize                        int
	Encapsulation                    uint16
	Lifetime                         time.Duration
}

type ESPDirectionalKeys struct {
	SPI                              uint32
	EncryptionKey, AuthenticationKey []byte
}
type ESPPair struct {
	Transform                        ESPTransform
	InitiatorCookie, ResponderCookie Cookie
	Inbound, Outbound                ESPDirectionalKeys
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
	if config.Encapsulation == 0 {
		config.Encapsulation = EncapsulationTransport
	}
	if config.Encapsulation != EncapsulationTransport && config.Encapsulation != EncapsulationNATTTransport {
		return nil, ErrInvalidCryptoInput
	}
	config.Secrets = cloneSecrets(config.Secrets)
	config.LastPhase1Block = append([]byte(nil), config.LastPhase1Block...)
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
	reply, err := q.handle(wire)
	if err != nil {
		q.fail()
	}
	return reply, err
}

func (q *QuickModeResponder) handle(wire []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("quick mode decrypt proposal: %w", err)
	}
	payloads, meaningful, err := decodePayloadsWithLength(packet.FirstPayload, plaintext)
	if err != nil {
		return nil, fmt.Errorf("quick mode decode proposal: %w", err)
	}
	if len(payloads) < 3 {
		return nil, fmt.Errorf("%w: quick mode proposal has %d payloads", ErrUnexpectedExchange, len(payloads))
	}
	hashPayload, ok := payloads[0].(DataPayload)
	if !ok || hashPayload.Kind != PayloadHash {
		return nil, fmt.Errorf("%w: quick mode first payload is not HASH", ErrUnexpectedExchange)
	}
	hashPayloadLength := int(binary.BigEndian.Uint16(plaintext[2:4]))
	if !VerifyPRF(q.config.Transform.Hash, q.config.Secrets.SKEYIDa, hashPayload.Data, messageIDBytes(q.messageID), plaintext[hashPayloadLength:meaningful]) {
		return nil, fmt.Errorf("%w: HASH(1)", ErrInvalidCryptoInput)
	}
	sa, ok := payloads[1].(SecurityAssociation)
	if !ok {
		return nil, fmt.Errorf("%w: quick mode second payload is not SA", ErrUnexpectedExchange)
	}
	nonce, ok := payloads[2].(DataPayload)
	if !ok || nonce.Kind != PayloadNonce || len(nonce.Data) < 16 {
		return nil, fmt.Errorf("%w: quick mode third payload is not a valid nonce", ErrUnexpectedExchange)
	}
	selectors, err := quickModeSelectors(payloads[3:])
	if err != nil {
		return nil, err
	}
	selectedSA, espTransform, outboundSPI, inboundSPI, err := selectESPsa(sa, q.config.Encapsulation, q.config.Random)
	if err != nil {
		return nil, err
	}
	if q.config.Lifetime > 0 {
		seconds := uint32(q.config.Lifetime / time.Second)
		if seconds == 0 {
			seconds = 1
		}
		if espTransform.LifetimeSeconds == 0 || seconds < espTransform.LifetimeSeconds {
			espTransform.LifetimeSeconds = seconds
			selected := &selectedSA.Proposals[0].Transforms[0]
			attributes := selected.Attributes[:0]
			for _, attribute := range selected.Attributes {
				if attribute.Type != AttributeP2LifeType && attribute.Type != AttributeP2LifeValue {
					attributes = append(attributes, attribute)
				}
			}
			selected.Attributes = append(attributes, TVAttribute(AttributeP2LifeType, LifeTypeSeconds), TLVAttribute(AttributeP2LifeValue, uint32Bytes(seconds)))
		}
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
	q.pair = ESPPair{Transform: espTransform, InitiatorCookie: q.config.InitiatorCookie, ResponderCookie: q.config.ResponderCookie,
		Inbound:  ESPDirectionalKeys{SPI: inboundSPI, EncryptionKey: append([]byte(nil), inKeymat[:espTransform.KeyBits/8]...), AuthenticationKey: append([]byte(nil), inKeymat[espTransform.KeyBits/8:]...)},
		Outbound: ESPDirectionalKeys{SPI: outboundSPI, EncryptionKey: append([]byte(nil), outKeymat[:espTransform.KeyBits/8]...), AuthenticationKey: append([]byte(nil), outKeymat[espTransform.KeyBits/8:]...)},
	}
	after := []Payload{selectedSA, DataPayload{Kind: PayloadNonce, Data: q.responderNonce}}
	after = append(after, selectors...)
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
	q.releaseExchangeSecrets()
	return nil, nil
}

// quickModeSelectors accepts either no explicit selectors or the IDci/IDcr
// pair used by transport-mode L2TP/IPsec clients. The responder echoes the
// accepted pair, binding it into HASH(2).
func quickModeSelectors(payloads []Payload) ([]Payload, error) {
	if len(payloads) == 0 {
		return nil, nil
	}
	if len(payloads) != 2 {
		return nil, ErrUnexpectedExchange
	}
	selectors := make([]Payload, 0, 2)
	for _, payload := range payloads {
		selector, ok := payload.(Identification)
		if !ok || (selector.IDType != IDIPv4Address && selector.IDType != IDIPv4Subnet) || (selector.ProtocolID != 0 && selector.ProtocolID != 17) || (selector.Port != 0 && selector.Port != 1701) {
			return nil, fmt.Errorf("%w: unsupported Quick Mode selector", ErrUnsupportedTransform)
		}
		want := 4
		if selector.IDType == IDIPv4Subnet {
			want = 8
		}
		if len(selector.Data) != want {
			return nil, ErrInvalidPayload
		}
		selector.Data = append([]byte(nil), selector.Data...)
		selectors = append(selectors, selector)
	}
	return selectors, nil
}

func (q *QuickModeResponder) fail() {
	q.state = QuickModeFailed
	q.Close()
}

func (q *QuickModeResponder) releaseExchangeSecrets() {
	zeroBytes(q.config.Secrets.SKEYID)
	zeroBytes(q.config.Secrets.SKEYIDd)
	zeroBytes(q.config.Secrets.SKEYIDa)
	zeroBytes(q.config.Secrets.SKEYIDe)
	zeroBytes(q.config.Secrets.Key)
	zeroBytes(q.config.LastPhase1Block)
	zeroBytes(q.initiatorNonce)
	zeroBytes(q.responderNonce)
	q.cipher = nil
}

// Close clears both exchange state and any not-yet-installed ESP keys.
func (q *QuickModeResponder) Close() {
	q.releaseExchangeSecrets()
	zeroBytes(q.pair.Inbound.EncryptionKey)
	zeroBytes(q.pair.Inbound.AuthenticationKey)
	zeroBytes(q.pair.Outbound.EncryptionKey)
	zeroBytes(q.pair.Outbound.AuthenticationKey)
	q.pair = ESPPair{}
	q.state = QuickModeFailed
}

func selectESPsa(sa SecurityAssociation, encapsulation uint16, random io.Reader) (SecurityAssociation, ESPTransform, uint32, uint32, error) {
	if sa.DOI != DOIIPsec || sa.Situation != SituationIdentityOnly {
		return SecurityAssociation{}, ESPTransform{}, 0, 0, ErrUnsupportedTransform
	}
	for _, proposal := range sa.Proposals {
		if proposal.ProtocolID != ProtocolESP || len(proposal.SPI) != 4 {
			continue
		}
		for _, candidate := range proposal.Transforms {
			transform, err := ParseESPTransform(candidate)
			if err != nil {
				continue
			}
			if transform.Encapsulation != encapsulation {
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
