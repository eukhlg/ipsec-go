package isakmp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var ErrUnexpectedExchange = errors.New("isakmp: unexpected exchange message")

type MainModeState uint8

const (
	MainModeAwaitSA MainModeState = iota
	MainModeAwaitKeyExchange
	MainModeAwaitAuthentication
	MainModeEstablished
	MainModeFailed
)

type MainModeConfig struct {
	PreSharedKey []byte
	ResponderID  Identification
	Random       io.Reader
	NonceSize    int
}

type MainModeResponder struct {
	config                           MainModeConfig
	state                            MainModeState
	initiatorCookie, responderCookie Cookie
	transform                        Phase1Transform
	selectedSA                       SecurityAssociation
	initiatorSA                      []byte
	dh                               *DHExchange
	initiatorPublic, responderPublic []byte
	initiatorNonce, responderNonce   []byte
	secrets                          Phase1Secrets
	cipher                           *CBCContext
	capabilities                     PeerCapabilities
}

func NewMainModeResponder(config MainModeConfig) (*MainModeResponder, error) {
	if len(config.PreSharedKey) == 0 {
		return nil, fmt.Errorf("%w: empty PSK", ErrInvalidCryptoInput)
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.NonceSize == 0 {
		config.NonceSize = 20
	}
	if config.NonceSize < 16 || config.NonceSize > 256 {
		return nil, fmt.Errorf("%w: nonce size", ErrInvalidCryptoInput)
	}
	if config.ResponderID.IDType == 0 {
		return nil, fmt.Errorf("%w: responder identity", ErrInvalidCryptoInput)
	}
	config.PreSharedKey = append([]byte(nil), config.PreSharedKey...)
	return &MainModeResponder{config: config}, nil
}

func (r *MainModeResponder) State() MainModeState           { return r.state }
func (r *MainModeResponder) Transform() Phase1Transform     { return r.transform }
func (r *MainModeResponder) Cookies() (Cookie, Cookie)      { return r.initiatorCookie, r.responderCookie }
func (r *MainModeResponder) Capabilities() PeerCapabilities { return r.capabilities }
func (r *MainModeResponder) Secrets() (Phase1Secrets, bool) {
	if r.state != MainModeEstablished {
		return Phase1Secrets{}, false
	}
	return cloneSecrets(r.secrets), true
}

func (r *MainModeResponder) NewQuickModeResponder(random io.Reader) (*QuickModeResponder, error) {
	if r.state != MainModeEstablished {
		return nil, ErrUnexpectedExchange
	}
	return NewQuickModeResponder(QuickModeConfig{Transform: r.transform, Secrets: r.secrets, InitiatorCookie: r.initiatorCookie, ResponderCookie: r.responderCookie, LastPhase1Block: r.cipher.CurrentIV(), Random: random})
}

func (r *MainModeResponder) Handle(wire []byte) ([]byte, error) {
	packet, err := DecodePacket(wire)
	if err != nil {
		return nil, err
	}
	if packet.Exchange != ExchangeIdentityProtect || packet.MessageID != 0 {
		return nil, ErrUnexpectedExchange
	}
	switch r.state {
	case MainModeAwaitSA:
		return r.handleSA(packet, wire)
	case MainModeAwaitKeyExchange:
		return r.handleKeyExchange(packet)
	case MainModeAwaitAuthentication:
		return r.handleAuthentication(packet)
	default:
		return nil, ErrUnexpectedExchange
	}
}

func (r *MainModeResponder) handleSA(packet Packet, wire []byte) ([]byte, error) {
	if packet.Flags != 0 || isZeroCookie(packet.InitiatorCookie) || !isZeroCookie(packet.ResponderCookie) || len(packet.Payloads) == 0 {
		return nil, ErrUnexpectedExchange
	}
	sa, ok := packet.Payloads[0].(SecurityAssociation)
	if !ok || sa.DOI != DOIIPsec || sa.Situation != SituationIdentityOnly {
		return nil, ErrUnexpectedExchange
	}
	selectedSA, transform, err := selectPhase1SA(sa)
	if err != nil {
		return nil, err
	}
	if len(wire) < headerSize+4 {
		return nil, ErrShortPacket
	}
	saLength := int(binary.BigEndian.Uint16(wire[headerSize+2 : headerSize+4]))
	if saLength < 4 || headerSize+saLength > len(wire) {
		return nil, ErrInvalidPayload
	}
	r.initiatorSA = append([]byte(nil), wire[headerSize:headerSize+saLength]...)
	r.capabilities = DetectPeerCapabilities(packet.Payloads[1:])
	r.initiatorCookie, r.transform, r.selectedSA = packet.InitiatorCookie, transform, selectedSA
	if _, err := io.ReadFull(r.config.Random, r.responderCookie[:]); err != nil {
		return nil, err
	}
	if isZeroCookie(r.responderCookie) {
		r.responderCookie[7] = 1
	}
	r.state = MainModeAwaitKeyExchange
	replyPayloads := []Payload{selectedSA}
	if r.capabilities.MicrosoftL2TP {
		replyPayloads = append(replyPayloads, DataPayload{Kind: PayloadVendorID, Data: VendorMicrosoftL2TP})
	}
	return (Packet{InitiatorCookie: r.initiatorCookie, ResponderCookie: r.responderCookie, Exchange: ExchangeIdentityProtect, Payloads: replyPayloads}).MarshalBinary()
}

func (r *MainModeResponder) handleKeyExchange(packet Packet) ([]byte, error) {
	if packet.Flags != 0 || packet.InitiatorCookie != r.initiatorCookie || packet.ResponderCookie != r.responderCookie {
		return nil, ErrUnexpectedExchange
	}
	ke, nonce, err := keyExchangeAndNonce(packet.Payloads)
	if err != nil {
		return nil, err
	}
	r.dh, err = NewDHExchange(r.transform.DHGroup, r.config.Random)
	if err != nil {
		return nil, err
	}
	r.initiatorPublic, r.initiatorNonce = ke, nonce
	r.responderPublic = r.dh.Public()
	r.responderNonce = make([]byte, r.config.NonceSize)
	if _, err := io.ReadFull(r.config.Random, r.responderNonce); err != nil {
		return nil, err
	}
	shared, err := r.dh.SharedSecret(r.initiatorPublic)
	if err != nil {
		return nil, err
	}
	r.secrets, err = DerivePhase1Secrets(r.transform, r.config.PreSharedKey, r.initiatorNonce, r.responderNonce, shared, r.initiatorCookie, r.responderCookie)
	if err != nil {
		return nil, err
	}
	iv, err := InitialPhase1IV(r.transform, r.initiatorPublic, r.responderPublic)
	if err != nil {
		return nil, err
	}
	r.cipher, err = NewCBCContext(r.transform, r.secrets.Key, iv)
	if err != nil {
		return nil, err
	}
	r.state = MainModeAwaitAuthentication
	return (Packet{InitiatorCookie: r.initiatorCookie, ResponderCookie: r.responderCookie, Exchange: ExchangeIdentityProtect, Payloads: []Payload{
		DataPayload{Kind: PayloadKeyExchange, Data: r.responderPublic}, DataPayload{Kind: PayloadNonce, Data: r.responderNonce},
	}}).MarshalBinary()
}

func (r *MainModeResponder) handleAuthentication(packet Packet) ([]byte, error) {
	if packet.Flags != FlagEncrypted || packet.InitiatorCookie != r.initiatorCookie || packet.ResponderCookie != r.responderCookie {
		return nil, ErrUnexpectedExchange
	}
	plaintext, err := r.cipher.Decrypt(packet.EncryptedPayload)
	if err != nil {
		return nil, r.fail(err)
	}
	payloads, err := DecodePayloads(packet.FirstPayload, plaintext)
	if err != nil || len(payloads) != 2 {
		return nil, r.fail(ErrUnexpectedExchange)
	}
	identity, ok := payloads[0].(Identification)
	if !ok {
		return nil, r.fail(ErrUnexpectedExchange)
	}
	hashPayload, ok := payloads[1].(DataPayload)
	if !ok || hashPayload.Kind != PayloadHash {
		return nil, r.fail(ErrUnexpectedExchange)
	}
	idBody, _ := identity.marshalBody()
	expected, err := MainModeHash(r.transform, r.secrets.SKEYID, r.initiatorPublic, r.responderPublic, r.initiatorCookie, r.responderCookie, r.initiatorSA, idBody, true)
	if err != nil || !VerifyPRFValue(expected, hashPayload.Data) {
		return nil, r.fail(fmt.Errorf("%w: HASH_I", ErrInvalidCryptoInput))
	}
	responderIDBody, _ := r.config.ResponderID.marshalBody()
	hashR, err := MainModeHash(r.transform, r.secrets.SKEYID, r.initiatorPublic, r.responderPublic, r.initiatorCookie, r.responderCookie, r.initiatorSA, responderIDBody, false)
	if err != nil {
		return nil, err
	}
	first, body, err := MarshalPayloads([]Payload{r.config.ResponderID, DataPayload{Kind: PayloadHash, Data: hashR}})
	if err != nil {
		return nil, err
	}
	ciphertext := r.cipher.Encrypt(body)
	r.state = MainModeEstablished
	zeroBytes(r.config.PreSharedKey)
	r.config.PreSharedKey = nil
	r.dh = nil
	return (Packet{InitiatorCookie: r.initiatorCookie, ResponderCookie: r.responderCookie, Exchange: ExchangeIdentityProtect, Flags: FlagEncrypted, FirstPayload: first, EncryptedPayload: ciphertext}).MarshalBinary()
}

func selectPhase1SA(sa SecurityAssociation) (SecurityAssociation, Phase1Transform, error) {
	for _, proposal := range sa.Proposals {
		if proposal.ProtocolID != ProtocolIKE || len(proposal.SPI) != 0 {
			continue
		}
		for _, candidate := range proposal.Transforms {
			transform, err := ParsePhase1Transform(candidate)
			if err != nil {
				continue
			}
			selectedProposal := Proposal{Number: proposal.Number, ProtocolID: ProtocolIKE, Transforms: []Transform{candidate}}
			return SecurityAssociation{DOI: sa.DOI, Situation: sa.Situation, Proposals: []Proposal{selectedProposal}}, transform, nil
		}
	}
	return SecurityAssociation{}, Phase1Transform{}, ErrUnsupportedTransform
}

func keyExchangeAndNonce(payloads []Payload) ([]byte, []byte, error) {
	if len(payloads) < 2 {
		return nil, nil, ErrUnexpectedExchange
	}
	ke, ok := payloads[0].(DataPayload)
	if !ok || ke.Kind != PayloadKeyExchange {
		return nil, nil, ErrUnexpectedExchange
	}
	nonce, ok := payloads[1].(DataPayload)
	if !ok || nonce.Kind != PayloadNonce || len(nonce.Data) < 16 {
		return nil, nil, ErrUnexpectedExchange
	}
	return append([]byte(nil), ke.Data...), append([]byte(nil), nonce.Data...), nil
}

func isZeroCookie(cookie Cookie) bool { var zero Cookie; return cookie == zero }
func VerifyPRFValue(expected, actual []byte) bool {
	return len(expected) == len(actual) && subtle.ConstantTimeCompare(expected, actual) == 1
}
func cloneSecrets(s Phase1Secrets) Phase1Secrets {
	return Phase1Secrets{SKEYID: append([]byte(nil), s.SKEYID...), SKEYIDd: append([]byte(nil), s.SKEYIDd...), SKEYIDa: append([]byte(nil), s.SKEYIDa...), SKEYIDe: append([]byte(nil), s.SKEYIDe...), Key: append([]byte(nil), s.Key...)}
}

func (r *MainModeResponder) fail(err error) error { r.Close(); r.state = MainModeFailed; return err }

// Close removes authentication and keying material when an SA fails or expires.
func (r *MainModeResponder) Close() {
	zeroBytes(r.config.PreSharedKey)
	r.config.PreSharedKey = nil
	zeroBytes(r.initiatorNonce)
	r.initiatorNonce = nil
	zeroBytes(r.responderNonce)
	r.responderNonce = nil
	zeroBytes(r.secrets.SKEYID)
	zeroBytes(r.secrets.SKEYIDd)
	zeroBytes(r.secrets.SKEYIDa)
	zeroBytes(r.secrets.SKEYIDe)
	zeroBytes(r.secrets.Key)
	r.secrets = Phase1Secrets{}
	r.dh = nil
	r.cipher = nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
