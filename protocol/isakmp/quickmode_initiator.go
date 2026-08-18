package isakmp

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

type QuickModeInitiatorConfig struct {
	Transform                        Phase1Transform
	Secrets                          Phase1Secrets
	InitiatorCookie, ResponderCookie Cookie
	LastPhase1Block                  []byte
	Random                           io.Reader
	MessageID                        uint32
	Previous                         ESPPair
	Lifetime                         time.Duration
}

// QuickModeInitiator performs a server-initiated, non-PFS Quick Mode rekey.
type QuickModeInitiator struct {
	config QuickModeInitiatorConfig
	cipher *CBCContext
	nonce  []byte
	pair   ESPPair
}

func NewQuickModeInitiator(config QuickModeInitiatorConfig) (*QuickModeInitiator, error) {
	if config.MessageID == 0 || config.Previous.Transform.Encryption == 0 || len(config.Secrets.SKEYIDa) == 0 || len(config.Secrets.SKEYIDd) == 0 || len(config.LastPhase1Block) == 0 || config.Random == nil {
		return nil, ErrInvalidCryptoInput
	}
	iv, err := Phase2IV(config.Transform, config.LastPhase1Block, config.MessageID)
	if err != nil {
		return nil, err
	}
	cipher, err := NewCBCContext(config.Transform, config.Secrets.Key, iv)
	if err != nil {
		return nil, err
	}
	config.Secrets = cloneSecrets(config.Secrets)
	config.LastPhase1Block = append([]byte(nil), config.LastPhase1Block...)
	return &QuickModeInitiator{config: config, cipher: cipher}, nil
}

func (q *QuickModeInitiator) Start() ([]byte, error) {
	spiBytes := make([]byte, 4)
	if _, err := io.ReadFull(q.config.Random, spiBytes); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(spiBytes) == 0 {
		spiBytes[3] = 1
	}
	q.nonce = make([]byte, 20)
	if _, err := io.ReadFull(q.config.Random, q.nonce); err != nil {
		return nil, err
	}
	t := q.config.Previous.Transform
	attrs := []Attribute{TVAttribute(AttributeP2Encapsulation, t.Encapsulation), TVAttribute(AttributeP2Authentication, t.Authentication), TVAttribute(AttributeP2KeyLength, uint16(t.KeyBits))}
	lifetime := q.config.Lifetime
	if lifetime <= 0 && t.LifetimeSeconds != 0 {
		lifetime = time.Duration(t.LifetimeSeconds) * time.Second
	}
	if lifetime > 0 {
		seconds := uint32(lifetime / time.Second)
		if seconds == 0 {
			seconds = 1
		}
		attrs = append(attrs, TVAttribute(AttributeP2LifeType, LifeTypeSeconds), TLVAttribute(AttributeP2LifeValue, uint32Bytes(seconds)))
	}
	sa := SecurityAssociation{DOI: DOIIPsec, Situation: SituationIdentityOnly, Proposals: []Proposal{{Number: 1, ProtocolID: ProtocolESP, SPI: spiBytes, Transforms: []Transform{{Number: 1, ID: t.Encryption, Attributes: attrs}}}}}
	after := []Payload{sa, DataPayload{Kind: PayloadNonce, Data: q.nonce}}
	_, afterWire, err := MarshalPayloads(after)
	if err != nil {
		return nil, err
	}
	hash, err := QuickModeHash1(q.config.Transform, q.config.Secrets.SKEYIDa, q.config.MessageID, afterWire)
	if err != nil {
		return nil, err
	}
	first, body, err := MarshalPayloads(append([]Payload{DataPayload{Kind: PayloadHash, Data: hash}}, after...))
	if err != nil {
		return nil, err
	}
	q.pair.Inbound.SPI = binary.BigEndian.Uint32(spiBytes)
	return (Packet{InitiatorCookie: q.config.InitiatorCookie, ResponderCookie: q.config.ResponderCookie, Exchange: ExchangeQuickMode, Flags: FlagEncrypted, MessageID: q.config.MessageID, FirstPayload: first, EncryptedPayload: q.cipher.Encrypt(body)}).MarshalBinary()
}

func (q *QuickModeInitiator) Handle(wire []byte) ([]byte, ESPPair, error) {
	packet, err := DecodePacket(wire)
	if err != nil || packet.Exchange != ExchangeQuickMode || packet.Flags != FlagEncrypted || packet.MessageID != q.config.MessageID || packet.InitiatorCookie != q.config.InitiatorCookie || packet.ResponderCookie != q.config.ResponderCookie {
		return nil, ESPPair{}, ErrUnexpectedExchange
	}
	plain, err := q.cipher.Decrypt(packet.EncryptedPayload)
	if err != nil {
		return nil, ESPPair{}, err
	}
	payloads, meaningful, err := decodePayloadsWithLength(packet.FirstPayload, plain)
	if err != nil || len(payloads) < 3 {
		return nil, ESPPair{}, ErrUnexpectedExchange
	}
	hp, ok := payloads[0].(DataPayload)
	if !ok || hp.Kind != PayloadHash {
		return nil, ESPPair{}, ErrUnexpectedExchange
	}
	sa, ok := payloads[1].(SecurityAssociation)
	if !ok {
		return nil, ESPPair{}, ErrUnexpectedExchange
	}
	nr, ok := payloads[2].(DataPayload)
	if !ok || nr.Kind != PayloadNonce || len(nr.Data) < 16 {
		return nil, ESPPair{}, ErrUnexpectedExchange
	}
	hashLen := int(binary.BigEndian.Uint16(plain[2:4]))
	want, _ := QuickModeHash2(q.config.Transform, q.config.Secrets.SKEYIDa, q.config.MessageID, q.nonce, plain[hashLen:meaningful])
	if !VerifyPRFValue(want, hp.Data) {
		return nil, ESPPair{}, fmt.Errorf("%w: HASH(2)", ErrInvalidCryptoInput)
	}
	selected, transform, outboundSPI, _, err := selectESPsa(sa, q.config.Previous.Transform.Encapsulation, zeroReader{})
	if err != nil {
		return nil, ESPPair{}, err
	}
	_ = selected
	// selectESPsa allocates a responder SPI; only its validation and offered SPI are needed here.
	keySize := transform.KeyBits/8 + 20
	inKM, err := DeriveESPKeyMaterial(q.config.Transform, q.config.Secrets.SKEYIDd, nil, ProtocolESP, uint32Bytes(q.pair.Inbound.SPI), q.nonce, nr.Data, keySize)
	if err != nil {
		return nil, ESPPair{}, err
	}
	outKM, err := DeriveESPKeyMaterial(q.config.Transform, q.config.Secrets.SKEYIDd, nil, ProtocolESP, uint32Bytes(outboundSPI), q.nonce, nr.Data, keySize)
	if err != nil {
		return nil, ESPPair{}, err
	}
	q.pair = ESPPair{Transform: transform, InitiatorCookie: q.config.InitiatorCookie, ResponderCookie: q.config.ResponderCookie, Inbound: ESPDirectionalKeys{SPI: q.pair.Inbound.SPI, EncryptionKey: append([]byte(nil), inKM[:transform.KeyBits/8]...), AuthenticationKey: append([]byte(nil), inKM[transform.KeyBits/8:]...)}, Outbound: ESPDirectionalKeys{SPI: outboundSPI, EncryptionKey: append([]byte(nil), outKM[:transform.KeyBits/8]...), AuthenticationKey: append([]byte(nil), outKM[transform.KeyBits/8:]...)}}
	hash3, _ := QuickModeHash3(q.config.Transform, q.config.Secrets.SKEYIDa, q.config.MessageID, q.nonce, nr.Data)
	first, body, err := MarshalPayloads([]Payload{DataPayload{Kind: PayloadHash, Data: hash3}})
	if err != nil {
		return nil, ESPPair{}, err
	}
	confirmation, err := (Packet{InitiatorCookie: q.config.InitiatorCookie, ResponderCookie: q.config.ResponderCookie, Exchange: ExchangeQuickMode, Flags: FlagEncrypted, MessageID: q.config.MessageID, FirstPayload: first, EncryptedPayload: q.cipher.Encrypt(body)}).MarshalBinary()
	return confirmation, clonePair(q.pair), err
}

func (q *QuickModeInitiator) Close() {
	zeroBytes(q.config.Secrets.SKEYID)
	zeroBytes(q.config.Secrets.SKEYIDd)
	zeroBytes(q.config.Secrets.SKEYIDa)
	zeroBytes(q.config.Secrets.SKEYIDe)
	zeroBytes(q.config.Secrets.Key)
	zeroBytes(q.config.LastPhase1Block)
	zeroBytes(q.nonce)
	zeroBytes(q.pair.Inbound.EncryptionKey)
	zeroBytes(q.pair.Inbound.AuthenticationKey)
	zeroBytes(q.pair.Outbound.EncryptionKey)
	zeroBytes(q.pair.Outbound.AuthenticationKey)
	q.config.Secrets = Phase1Secrets{}
	q.config.LastPhase1Block = nil
	q.nonce = nil
	q.pair = ESPPair{}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 1
	}
	return len(p), nil
}
