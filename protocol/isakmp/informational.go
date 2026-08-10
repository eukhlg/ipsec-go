package isakmp

import (
	"encoding/binary"
	"fmt"
)

// DecodeInformational authenticates and decrypts one Phase 1 informational
// exchange. Informational exchanges use a message-specific Phase 2 IV and do
// not advance the Main Mode CBC state.
func (r *MainModeResponder) DecodeInformational(wire []byte) (uint32, []Payload, error) {
	if r.state != MainModeEstablished || r.cipher == nil {
		return 0, nil, ErrUnexpectedExchange
	}
	packet, err := DecodePacket(wire)
	if err != nil {
		return 0, nil, err
	}
	if packet.Exchange != ExchangeInformational || packet.Flags != FlagEncrypted || packet.MessageID == 0 || packet.InitiatorCookie != r.initiatorCookie || packet.ResponderCookie != r.responderCookie {
		return 0, nil, ErrUnexpectedExchange
	}
	cipher, err := r.exchangeCipher(packet.MessageID)
	if err != nil {
		return 0, nil, err
	}
	plaintext, err := cipher.Decrypt(packet.EncryptedPayload)
	if err != nil {
		return 0, nil, err
	}
	payloads, meaningful, err := decodePayloadsWithLength(packet.FirstPayload, plaintext)
	if err != nil || len(payloads) < 1 {
		return 0, nil, ErrUnexpectedExchange
	}
	hashPayload, ok := payloads[0].(DataPayload)
	if !ok || hashPayload.Kind != PayloadHash || len(plaintext) < 4 {
		return 0, nil, ErrUnexpectedExchange
	}
	hashLength := int(binary.BigEndian.Uint16(plaintext[2:4]))
	if hashLength < 4 || hashLength > meaningful || !VerifyPRF(r.transform.Hash, r.secrets.SKEYIDa, hashPayload.Data, messageIDBytes(packet.MessageID), plaintext[hashLength:meaningful]) {
		return 0, nil, fmt.Errorf("%w: informational HASH", ErrInvalidCryptoInput)
	}
	return packet.MessageID, payloads[1:], nil
}

// EncodeInformational creates an authenticated encrypted informational packet.
func (r *MainModeResponder) EncodeInformational(messageID uint32, payloads []Payload) ([]byte, error) {
	if r.state != MainModeEstablished || messageID == 0 || len(payloads) == 0 {
		return nil, ErrUnexpectedExchange
	}
	_, afterWire, err := MarshalPayloads(payloads)
	if err != nil {
		return nil, err
	}
	hashValue, err := PRF(r.transform.Hash, r.secrets.SKEYIDa, messageIDBytes(messageID), afterWire)
	if err != nil {
		return nil, err
	}
	first, body, err := MarshalPayloads(append([]Payload{DataPayload{Kind: PayloadHash, Data: hashValue}}, payloads...))
	if err != nil {
		return nil, err
	}
	cipher, err := r.exchangeCipher(messageID)
	if err != nil {
		return nil, err
	}
	return (Packet{InitiatorCookie: r.initiatorCookie, ResponderCookie: r.responderCookie, Exchange: ExchangeInformational, Flags: FlagEncrypted, MessageID: messageID, FirstPayload: first, EncryptedPayload: cipher.Encrypt(body)}).MarshalBinary()
}

func (r *MainModeResponder) exchangeCipher(messageID uint32) (*CBCContext, error) {
	iv, err := Phase2IV(r.transform, r.cipher.CurrentIV(), messageID)
	if err != nil {
		return nil, err
	}
	return NewCBCContext(r.transform, r.secrets.Key, iv)
}

func ikeDeleteSPI(initiator, responder Cookie) []byte {
	spi := make([]byte, 0, 16)
	spi = append(spi, initiator[:]...)
	return append(spi, responder[:]...)
}
