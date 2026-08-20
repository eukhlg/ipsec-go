package isakmp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	ErrUnknownSA = errors.New("isakmp: unknown security association")
	ErrSALimit   = errors.New("isakmp: security association limit reached")
)

type ControlPlaneConfig struct {
	PreSharedKey      []byte
	ResponderID       Identification
	ResponderEndpoint netip.AddrPort
	Random            io.Reader
	MaxPhase1SAs      int
	MaxHalfOpen       int
	MaxSAsPerPeer     int
	Phase1Lifetime    time.Duration
	ESPLifetime       time.Duration
	DPDInterval       time.Duration
	ForceNATT         bool
	Debugf            func(string, ...any)
	HandshakeTimeout  time.Duration
	QuickModeTimeout  time.Duration
}

type ControlPlaneResult struct {
	Reply       []byte
	Established *ESPPair
	Lifecycle   []LifecycleEvent
}

type LifecycleEventType uint8

const (
	LifecycleDeleteESP LifecycleEventType = iota + 1
	LifecycleDeleteIKE
	LifecycleExpireIKE
	LifecycleRebindIKE
)

type LifecycleEvent struct {
	Type              LifecycleEventType
	ResponderCookie   Cookie
	ReplacementCookie Cookie
	SPIs              []uint32
}

type ControlDatagram struct {
	Peer    net.Addr
	Payload []byte
	NATT    bool
}

type controlSA struct {
	peer            string
	peerIP          netip.Addr
	peerAddr        net.Addr
	natt            bool
	main            *MainModeResponder
	quick           map[uint32]*QuickModeResponder
	quickInitiated  map[uint32]*QuickModeInitiator
	quickUpdated    map[uint32]time.Time
	responses       map[string][]byte
	responseOrder   []string
	updated         time.Time
	established     time.Time
	expires         time.Time
	softExpired     bool
	nextDPD         time.Time
	dpdSequence     uint32
	dpdOutstanding  bool
	dpdFailures     int
	activePair      ESPPair
	pairEstablished time.Time
	nextRekey       time.Time
	rekeyFailures   int
	rekeyRetryAt    time.Time
	predecessors    []Cookie
	successor       Cookie
}

const maxProactiveRekeyAttempts = 3

type ControlPlane struct {
	mu      sync.Mutex
	config  ControlPlaneConfig
	sas     map[Cookie]*controlSA
	pending []LifecycleEvent
}

func NewControlPlane(config ControlPlaneConfig) (*ControlPlane, error) {
	if len(config.PreSharedKey) == 0 || config.ResponderID.IDType == 0 {
		return nil, ErrInvalidCryptoInput
	}
	if config.ResponderEndpoint.IsValid() && !config.ResponderEndpoint.Addr().Is4() {
		return nil, ErrInvalidCryptoInput
	}
	if config.MaxPhase1SAs == 0 {
		config.MaxPhase1SAs = 1024
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.MaxPhase1SAs < 0 || config.MaxHalfOpen < 0 || config.MaxSAsPerPeer < 0 || config.ESPLifetime < 0 || config.DPDInterval < 0 {
		return nil, ErrInvalidCryptoInput
	}
	if config.Phase1Lifetime == 0 {
		config.Phase1Lifetime = 8 * time.Hour
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 30 * time.Second
	}
	if config.QuickModeTimeout == 0 {
		config.QuickModeTimeout = 10 * time.Second
	}
	if config.HandshakeTimeout < 0 || config.QuickModeTimeout < 0 || config.Phase1Lifetime < 0 {
		return nil, ErrInvalidCryptoInput
	}
	return &ControlPlane{config: config, sas: make(map[Cookie]*controlSA)}, nil
}

func (c *ControlPlane) HandleDatagram(peer net.Addr, wire []byte, now time.Time) (ControlPlaneResult, error) {
	return c.handleDatagram(peer, wire, now, false)
}

// HandleNATTDatagram processes marker-prefixed IKE received on the local
// UDP/4500 socket. A NAT may map the peer's source port to any value.
func (c *ControlPlane) HandleNATTDatagram(peer net.Addr, wire []byte, now time.Time) (ControlPlaneResult, error) {
	return c.handleDatagram(peer, wire, now, true)
}

func (c *ControlPlane) handleDatagram(peer net.Addr, wire []byte, now time.Time, viaNATT bool) (ControlPlaneResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	packet, err := DecodePacket(wire)
	if err != nil {
		c.debug("ike decode rejected peer=%s bytes=%d error=%v", peer, len(wire), err)
		return ControlPlaneResult{}, err
	}
	c.debug("ike rx peer=%s exchange=%d message_id=%08x flags=%02x initiator_cookie=%x responder_cookie=%x bytes=%d natt=%t", peer, packet.Exchange, packet.MessageID, packet.Flags, packet.InitiatorCookie, packet.ResponderCookie, len(wire), viaNATT)
	c.expire(now)
	if isZeroCookie(packet.ResponderCookie) {
		if packet.Exchange != ExchangeIdentityProtect || packet.MessageID != 0 {
			return ControlPlaneResult{}, ErrUnknownSA
		}
		for _, existing := range c.sas {
			initiatorCookie, _ := existing.main.Cookies()
			if existing.peer == addressKey(peer) && initiatorCookie == packet.InitiatorCookie {
				if reply, ok := existing.responses[string(wire)]; ok {
					return ControlPlaneResult{Reply: append([]byte(nil), reply...)}, nil
				}
			}
		}
		remoteEndpoint, ok := addressPort(peer)
		if c.config.ResponderEndpoint.IsValid() && !ok {
			return ControlPlaneResult{}, ErrUnknownSA
		}
		halfOpen, perPeer := 0, 0
		for _, existing := range c.sas {
			if existing.main.State() != MainModeEstablished {
				halfOpen++
			}
			if remoteEndpoint.IsValid() && existing.peerIP == remoteEndpoint.Addr() {
				perPeer++
			}
		}
		if len(c.sas) >= c.config.MaxPhase1SAs || (c.config.MaxHalfOpen > 0 && halfOpen >= c.config.MaxHalfOpen) || (c.config.MaxSAsPerPeer > 0 && perPeer >= c.config.MaxSAsPerPeer) {
			c.debug("ike SA limit rejected peer=%s total=%d half_open=%d per_peer=%d limits=%d/%d/%d", peer, len(c.sas), halfOpen, perPeer, c.config.MaxPhase1SAs, c.config.MaxHalfOpen, c.config.MaxSAsPerPeer)
			return ControlPlaneResult{}, ErrSALimit
		}
		main, err := NewMainModeResponder(MainModeConfig{PreSharedKey: c.config.PreSharedKey, ResponderID: c.config.ResponderID, LocalEndpoint: c.config.ResponderEndpoint, RemoteEndpoint: remoteEndpoint, Random: c.config.Random, ForceNATT: c.config.ForceNATT, ESPLifetime: c.config.ESPLifetime})
		if err != nil {
			return ControlPlaneResult{}, err
		}
		reply, err := main.Handle(wire)
		if err != nil {
			return ControlPlaneResult{}, err
		}
		_, responderCookie := main.Cookies()
		if _, collision := c.sas[responderCookie]; collision {
			return ControlPlaneResult{}, fmt.Errorf("%w: responder cookie collision", ErrInvalidCryptoInput)
		}
		lifetime := c.config.Phase1Lifetime
		if seconds := main.Transform().LifetimeSeconds; seconds != 0 && time.Duration(seconds)*time.Second < lifetime {
			lifetime = time.Duration(seconds) * time.Second
		}
		runtime := &controlSA{peer: addressKey(peer), peerIP: remoteEndpoint.Addr(), peerAddr: cloneNetAddr(peer), natt: viaNATT, main: main, quick: make(map[uint32]*QuickModeResponder), quickInitiated: make(map[uint32]*QuickModeInitiator), quickUpdated: make(map[uint32]time.Time), responses: make(map[string][]byte), updated: now, expires: now.Add(lifetime)}
		runtime.cacheResponse(wire, reply)
		c.sas[responderCookie] = runtime
		selected := main.Transform()
		c.debug("ike main state peer=%s state=await-key-exchange responder_cookie=%x encryption=%d hash=%d dh=%d key_bits=%d lifetime=%ds", peer, responderCookie, selected.Encryption, selected.Hash, selected.DHGroup, selected.KeyBits, selected.LifetimeSeconds)
		return ControlPlaneResult{Reply: reply}, nil
	}
	sa := c.sas[packet.ResponderCookie]
	if sa == nil {
		return ControlPlaneResult{}, ErrUnknownSA
	}
	migratePeer := false
	if sa.peer != addressKey(peer) {
		migrated, ok := addressPort(peer)
		if !viaNATT || !ok || !migrated.Addr().IsValid() || migrated.Addr() != sa.peerIP || !sa.main.NATTraversal() {
			return ControlPlaneResult{}, ErrUnknownSA
		}
		migratePeer = true
		c.debug("natt migration candidate peer=%s responder_cookie=%x", peer, packet.ResponderCookie)
	}
	if reply, ok := sa.responses[string(wire)]; ok {
		if migratePeer {
			sa.peer = addressKey(peer)
			sa.peerAddr, sa.natt = cloneNetAddr(peer), true
		}
		return ControlPlaneResult{Reply: append([]byte(nil), reply...)}, nil
	}
	var reply []byte
	var established *ESPPair
	var lifecycle []LifecycleEvent
	switch packet.Exchange {
	case ExchangeIdentityProtect:
		wasEstablished := sa.main.State() == MainModeEstablished
		reply, err = sa.main.Handle(wire)
		if err != nil && sa.main.State() == MainModeFailed {
			lifecycle = append(lifecycle, c.closeControlSA(packet.ResponderCookie)...)
		}
		if err == nil && !wasEstablished && sa.main.State() == MainModeEstablished {
			sa.established = now
			lifecycle = append(lifecycle, c.adoptPhase1Replacement(packet.ResponderCookie, sa)...)
		}
	case ExchangeQuickMode:
		if initiated := sa.quickInitiated[packet.MessageID]; initiated != nil {
			reply, pair, initiateErr := initiated.Handle(wire)
			initiated.Close()
			if initiateErr != nil {
				delete(sa.quickInitiated, packet.MessageID)
				delete(sa.quickUpdated, packet.MessageID)
				c.noteProactiveRekeyFailure(packet.ResponderCookie, sa, now)
				return ControlPlaneResult{}, initiateErr
			}
			delete(sa.quickInitiated, packet.MessageID)
			delete(sa.quickUpdated, packet.MessageID)
			sa.recordPair(pair, now)
			sa.cacheResponse(wire, reply)
			sa.updated = now
			c.debug("quick proactive established peer=%s origin=server message_id=%08x inbound_spi=%08x outbound_spi=%08x lifetime=%ds lifetime_kb=%d", peer, packet.MessageID, pair.Inbound.SPI, pair.Outbound.SPI, pair.Transform.LifetimeSeconds, pair.Transform.LifetimeKilobytes)
			return ControlPlaneResult{Reply: reply, Established: &pair, Lifecycle: lifecycle}, nil
		}
		quick := sa.quick[packet.MessageID]
		if quick == nil {
			quick, err = sa.main.NewQuickModeResponder(c.config.Random)
			if err == nil {
				sa.quick[packet.MessageID] = quick
				sa.quickUpdated[packet.MessageID] = now
			}
		}
		if err == nil {
			reply, err = quick.Handle(wire)
		}
		if err != nil {
			if quick != nil {
				quick.Close()
			}
			delete(sa.quick, packet.MessageID)
			delete(sa.quickUpdated, packet.MessageID)
		}
		if err == nil {
			sa.quickUpdated[packet.MessageID] = now
			if pair, ok := quick.Pair(); ok {
				previousPairEstablished := sa.pairEstablished
				established = &pair
				sa.recordPair(pair, now)
				sincePrevious := time.Duration(0)
				if !previousPairEstablished.IsZero() {
					sincePrevious = now.Sub(previousPairEstablished)
				}
				c.debug("quick established peer=%s origin=peer message_id=%08x inbound_spi=%08x outbound_spi=%08x encryption=%d key_bits=%d encapsulation=%d lifetime=%ds lifetime_kb=%d since_previous=%s", peer, packet.MessageID, pair.Inbound.SPI, pair.Outbound.SPI, pair.Transform.Encryption, pair.Transform.KeyBits, pair.Transform.Encapsulation, pair.Transform.LifetimeSeconds, pair.Transform.LifetimeKilobytes, sincePrevious)
				quick.Close()
				delete(sa.quick, packet.MessageID)
				delete(sa.quickUpdated, packet.MessageID)
			}
		}
	case ExchangeInformational:
		reply, lifecycle, err = c.handleInformational(sa, packet.ResponderCookie, wire)
		if err == nil {
			sa.updated = now
			sa.dpdOutstanding, sa.dpdFailures = false, 0
			if c.config.DPDInterval > 0 {
				sa.nextDPD = now.Add(c.config.DPDInterval)
			}
			if len(lifecycle) != 0 {
				for _, event := range lifecycle {
					if event.Type == LifecycleDeleteIKE {
						fallback := c.closeControlSA(packet.ResponderCookie)
						lifecycle = append(fallback, lifecycle...)
						break
					}
				}
				return ControlPlaneResult{Reply: append([]byte(nil), reply...), Lifecycle: lifecycle}, nil
			}
		}
	default:
		err = ErrUnexpectedExchange
	}
	if err != nil {
		return ControlPlaneResult{}, err
	}
	if migratePeer {
		sa.peer = addressKey(peer)
		sa.peerAddr, sa.natt = cloneNetAddr(peer), true
	}
	if sa.main.State() == MainModeEstablished {
		nat, complete := sa.main.NATDetection()
		c.debug("ike main established peer=%s responder_cookie=%x natt=%t nat_detection_complete=%t local_nat=%t remote_nat=%t", peer, packet.ResponderCookie, sa.main.NATTraversal(), complete, nat.LocalNAT, nat.RemoteNAT)
	}
	sa.cacheResponse(wire, reply)
	sa.updated = now
	sa.dpdOutstanding, sa.dpdFailures = false, 0
	if c.config.DPDInterval > 0 {
		sa.nextDPD = now.Add(c.config.DPDInterval)
	}
	return ControlPlaneResult{Reply: append([]byte(nil), reply...), Established: established, Lifecycle: lifecycle}, nil
}

func (c *ControlPlane) handleInformational(sa *controlSA, responderCookie Cookie, wire []byte) ([]byte, []LifecycleEvent, error) {
	requestID, payloads, err := sa.main.DecodeInformational(wire)
	if err != nil {
		return nil, nil, err
	}
	var events []LifecycleEvent
	var replyPayloads []Payload
	for _, payload := range payloads {
		switch value := payload.(type) {
		case Delete:
			if value.DOI != DOIIPsec {
				return nil, nil, ErrInvalidPayload
			}
			switch value.ProtocolID {
			case ProtocolESP:
				var spis []uint32
				for _, spi := range value.SPIs {
					if len(spi) != 4 {
						return nil, nil, ErrInvalidPayload
					}
					spis = append(spis, binary.BigEndian.Uint32(spi))
				}
				events = append(events, LifecycleEvent{Type: LifecycleDeleteESP, ResponderCookie: responderCookie, SPIs: spis})
			case ProtocolIKE:
				if len(value.SPIs) != 1 || !bytes.Equal(value.SPIs[0], ikeDeleteSPI(sa.main.initiatorCookie, sa.main.responderCookie)) {
					return nil, nil, ErrInvalidPayload
				}
				events = append(events, LifecycleEvent{Type: LifecycleDeleteIKE, ResponderCookie: responderCookie})
			default:
				return nil, nil, ErrInvalidPayload
			}
		case Notification:
			if value.MessageType != NotifyRThere && value.MessageType != NotifyRThereACK {
				continue
			}
			if value.DOI != DOIIPsec || value.ProtocolID != ProtocolIKE || len(value.SPI) != 16 || len(value.Data) != 4 || !bytes.Equal(value.SPI, ikeDeleteSPI(sa.main.initiatorCookie, sa.main.responderCookie)) {
				return nil, nil, ErrInvalidPayload
			}
			if value.MessageType == NotifyRThere {
				replyPayloads = append(replyPayloads, Notification{DOI: DOIIPsec, ProtocolID: ProtocolIKE, SPI: append([]byte(nil), value.SPI...), MessageType: NotifyRThereACK, Data: append([]byte(nil), value.Data...)})
			}
		default:
			return nil, nil, ErrUnexpectedExchange
		}
	}
	if len(replyPayloads) == 0 {
		return nil, events, nil
	}
	messageID, err := c.newMessageID(requestID)
	if err != nil {
		return nil, nil, err
	}
	reply, err := sa.main.EncodeInformational(messageID, replyPayloads)
	return reply, events, err
}

// PollDPD creates proactive RFC 3706 probes and retires peers that miss three
// consecutive intervals. Any authenticated IKE traffic clears the probe.
func (c *ControlPlane) PollDPD(now time.Time) []ControlDatagram {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.config.DPDInterval <= 0 {
		return nil
	}
	var datagrams []ControlDatagram
	for cookie, sa := range c.sas {
		if sa.main.State() != MainModeEstablished || !isZeroCookie(sa.successor) || !sa.main.Capabilities().DPD || sa.peerAddr == nil {
			continue
		}
		if sa.nextDPD.IsZero() {
			sa.nextDPD = now.Add(c.config.DPDInterval)
			continue
		}
		if now.Before(sa.nextDPD) {
			continue
		}
		if sa.dpdOutstanding {
			sa.dpdFailures++
			if sa.dpdFailures >= 3 {
				c.debug("ipsec lifecycle DPD timeout peer=%s responder_cookie=%x", sa.peerAddr, cookie)
				c.pending = append(c.pending, c.closeControlSA(cookie)...)
				c.pending = append(c.pending, LifecycleEvent{Type: LifecycleExpireIKE, ResponderCookie: cookie})
				continue
			}
		} else {
			sa.dpdSequence++
			if sa.dpdSequence == 0 {
				sa.dpdSequence = 1
			}
		}
		data := uint32Bytes(sa.dpdSequence)
		payload := Notification{DOI: DOIIPsec, ProtocolID: ProtocolIKE, SPI: ikeDeleteSPI(sa.main.initiatorCookie, sa.main.responderCookie), MessageType: NotifyRThere, Data: data}
		messageID, err := c.newMessageID(0)
		if err != nil {
			continue
		}
		wire, err := sa.main.EncodeInformational(messageID, []Payload{payload})
		if err != nil {
			continue
		}
		datagrams = append(datagrams, ControlDatagram{Peer: cloneNetAddr(sa.peerAddr), Payload: wire, NATT: sa.natt})
		c.debug("ipsec lifecycle DPD tx peer=%s responder_cookie=%x sequence=%d retry=%d natt=%t", sa.peerAddr, cookie, sa.dpdSequence, sa.dpdFailures, sa.natt)
		sa.dpdOutstanding = true
		sa.nextDPD = now.Add(c.config.DPDInterval)
	}
	return datagrams
}

// PollRekey starts a replacement child SA before the negotiated ESP lifetime
// expires. The old SA remains installed until the authenticated exchange ends.
func (c *ControlPlane) PollRekey(now time.Time) []ControlDatagram {
	c.mu.Lock()
	defer c.mu.Unlock()
	var datagrams []ControlDatagram
	for cookie, sa := range c.sas {
		if sa.main.State() != MainModeEstablished || !isZeroCookie(sa.successor) || sa.peerAddr == nil || sa.activePair.Transform.Encryption == 0 || sa.nextRekey.IsZero() || now.Before(sa.nextRekey) || (!sa.rekeyRetryAt.IsZero() && now.Before(sa.rekeyRetryAt)) || sa.rekeyFailures >= maxProactiveRekeyAttempts || len(sa.quickInitiated) != 0 {
			continue
		}
		messageID, err := c.newMessageID(0)
		if err != nil {
			continue
		}
		quick, err := sa.main.NewQuickModeInitiator(c.config.Random, messageID, sa.activePair)
		if err != nil {
			continue
		}
		wire, err := quick.Start()
		if err != nil {
			quick.Close()
			continue
		}
		sa.quickInitiated[messageID] = quick
		sa.quickUpdated[messageID] = now
		datagrams = append(datagrams, ControlDatagram{Peer: cloneNetAddr(sa.peerAddr), Payload: wire, NATT: sa.natt})
		c.debug("quick proactive tx peer=%s responder_cookie=%x message_id=%08x attempt=%d/%d", sa.peerAddr, cookie, messageID, sa.rekeyFailures+1, maxProactiveRekeyAttempts)
	}
	return datagrams
}

func (c *ControlPlane) debug(format string, args ...any) {
	if c.config.Debugf != nil {
		c.config.Debugf(format, args...)
	}
}

func (c *ControlPlane) newMessageID(exclude uint32) (uint32, error) {
	var raw [4]byte
	for attempts := 0; attempts < 8; attempts++ {
		if _, err := io.ReadFull(c.config.Random, raw[:]); err != nil {
			return 0, err
		}
		value := binary.BigEndian.Uint32(raw[:])
		if value != 0 && value != exclude {
			return value, nil
		}
	}
	return 0, ErrInvalidCryptoInput
}

func (c *ControlPlane) expire(now time.Time) {
	for cookie, sa := range c.sas {
		for messageID, quick := range sa.quick {
			if now.Sub(sa.quickUpdated[messageID]) >= c.config.QuickModeTimeout {
				quick.Close()
				delete(sa.quick, messageID)
				delete(sa.quickUpdated, messageID)
			}
		}
		for messageID := range sa.quickInitiated {
			if now.Sub(sa.quickUpdated[messageID]) >= c.config.QuickModeTimeout {
				sa.quickInitiated[messageID].Close()
				delete(sa.quickInitiated, messageID)
				delete(sa.quickUpdated, messageID)
				c.noteProactiveRekeyFailure(cookie, sa, now)
			}
		}
		established := sa.main.State() == MainModeEstablished
		handshakeExpired := !established && now.Sub(sa.updated) >= c.config.HandshakeTimeout
		negotiationExpired := !established && !now.Before(sa.expires)
		if established && !sa.softExpired && !now.Before(sa.expires) {
			sa.softExpired = true
			c.debug("ike phase1 soft lifetime reached peer=%s responder_cookie=%x; retaining SA while awaiting peer replacement", sa.peerAddr, cookie)
		}
		if handshakeExpired || negotiationExpired {
			c.pending = append(c.pending, c.closeControlSA(cookie)...)
			c.pending = append(c.pending, LifecycleEvent{Type: LifecycleExpireIKE, ResponderCookie: cookie})
		}
	}
}

// Maintain expires SAs and returns lifecycle work for the ESP registry.
func (c *ControlPlane) Maintain(now time.Time) []LifecycleEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(now)
	events := append([]LifecycleEvent(nil), c.pending...)
	c.pending = nil
	return events
}

// Shutdown builds authenticated IKE delete notifications and clears all
// control-plane state. Callers should send the returned datagrams before
// closing UDP/500 and UDP/4500.
func (c *ControlPlane) Shutdown() []ControlDatagram {
	c.mu.Lock()
	defer c.mu.Unlock()
	var datagrams []ControlDatagram
	for cookie, sa := range c.sas {
		if sa.main.State() == MainModeEstablished && sa.peerAddr != nil {
			if messageID, err := c.newMessageID(0); err == nil {
				payload := Delete{DOI: DOIIPsec, ProtocolID: ProtocolIKE, SPIs: [][]byte{ikeDeleteSPI(sa.main.initiatorCookie, sa.main.responderCookie)}}
				if wire, err := sa.main.EncodeInformational(messageID, []Payload{payload}); err == nil {
					datagrams = append(datagrams, ControlDatagram{Peer: cloneNetAddr(sa.peerAddr), Payload: wire, NATT: sa.natt})
				}
			}
		}
		c.closeControlSA(cookie)
	}
	c.pending = nil
	return datagrams
}

func (c *ControlPlane) SACount() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.sas) }
func (sa *controlSA) cacheResponse(request, reply []byte) {
	key := string(request)
	if _, exists := sa.responses[key]; !exists {
		sa.responseOrder = append(sa.responseOrder, key)
	}
	sa.responses[key] = append([]byte(nil), reply...)
	for len(sa.responseOrder) > 8 {
		old := sa.responseOrder[0]
		sa.responseOrder = sa.responseOrder[1:]
		delete(sa.responses, old)
	}
}

func (sa *controlSA) recordPair(pair ESPPair, now time.Time) {
	sa.clearPair()
	sa.activePair = clonePair(pair)
	sa.pairEstablished = now
	sa.rekeyFailures = 0
	sa.rekeyRetryAt = time.Time{}
	lifetime := time.Duration(pair.Transform.LifetimeSeconds) * time.Second
	if lifetime <= 0 {
		return
	}
	lead := lifetime / 10
	if lead < time.Second {
		lead = time.Second
	}
	sa.nextRekey = now.Add(lifetime - lead)
}

func proactiveRekeyBackoff(failures int) time.Duration {
	delay := 30 * time.Second
	for i := 1; i < failures; i++ {
		delay *= 2
	}
	return delay
}

func (c *ControlPlane) noteProactiveRekeyFailure(cookie Cookie, sa *controlSA, now time.Time) {
	sa.rekeyFailures++
	if sa.rekeyFailures >= maxProactiveRekeyAttempts {
		sa.rekeyRetryAt = time.Time{}
		c.debug("quick proactive suppressed peer=%s responder_cookie=%x failures=%d; awaiting peer-initiated rekey", sa.peerAddr, cookie, sa.rekeyFailures)
		return
	}
	delay := proactiveRekeyBackoff(sa.rekeyFailures)
	sa.rekeyRetryAt = now.Add(delay)
	c.debug("quick proactive failed peer=%s responder_cookie=%x failures=%d retry_in=%s", sa.peerAddr, cookie, sa.rekeyFailures, delay)
}

func (sa *controlSA) clearPair() {
	zeroBytes(sa.activePair.Inbound.EncryptionKey)
	zeroBytes(sa.activePair.Inbound.AuthenticationKey)
	zeroBytes(sa.activePair.Outbound.EncryptionKey)
	zeroBytes(sa.activePair.Outbound.AuthenticationKey)
	sa.activePair = ESPPair{}
	sa.pairEstablished = time.Time{}
}

func (c *ControlPlane) closeControlSA(cookie Cookie) []LifecycleEvent {
	sa := c.sas[cookie]
	if sa == nil {
		return nil
	}
	var events []LifecycleEvent
	var fallbackCookie Cookie
	var fallback *controlSA
	for _, predecessorCookie := range sa.predecessors {
		if predecessor := c.sas[predecessorCookie]; predecessor != nil && predecessor.successor == cookie {
			predecessor.successor = Cookie{}
			if fallback == nil || predecessor.established.After(fallback.established) {
				fallbackCookie, fallback = predecessorCookie, predecessor
			}
		}
	}
	if fallback != nil && sa.activePair.Transform.Encryption != 0 {
		events = append(events, LifecycleEvent{Type: LifecycleRebindIKE, ResponderCookie: cookie, ReplacementCookie: fallbackCookie})
		c.debug("ike phase1 child ownership restored from_cookie=%x to_cookie=%x", cookie, fallbackCookie)
	}
	if !isZeroCookie(sa.successor) {
		if successor := c.sas[sa.successor]; successor != nil {
			successor.predecessors = removeCookie(successor.predecessors, cookie)
		}
	}
	for _, quick := range sa.quick {
		quick.Close()
	}
	for _, quick := range sa.quickInitiated {
		quick.Close()
	}
	sa.clearPair()
	sa.main.Close()
	delete(c.sas, cookie)
	return events
}

// Keep multiple responder-created Phase 1 SAs for one authenticated client and
// switch to the replacement after the peer completes a fresh Main Mode. Inherit
// the active child association to the replacement without changing its keys,
// SPIs, sequence numbers, or remaining lifetime.
func (c *ControlPlane) adoptPhase1Replacement(cookie Cookie, replacement *controlSA) []LifecycleEvent {
	replacementID, ok := replacement.main.PeerIdentity()
	if !ok {
		return nil
	}
	var newest *controlSA
	var newestCookie Cookie
	var events []LifecycleEvent
	for candidateCookie, candidate := range c.sas {
		if candidateCookie == cookie || candidate.main.State() != MainModeEstablished || candidate.peerIP != replacement.peerIP || !samePeerIdentity(candidate.main, replacementID) {
			continue
		}
		replacement.predecessors = append(replacement.predecessors, candidateCookie)
		candidate.successor = cookie
		events = append(events, LifecycleEvent{Type: LifecycleRebindIKE, ResponderCookie: candidateCookie, ReplacementCookie: cookie})
		if newest == nil || candidate.established.After(newest.established) {
			newest, newestCookie = candidate, candidateCookie
		}
	}
	if newest == nil {
		return nil
	}
	if newest.activePair.Transform.Encryption != 0 {
		replacement.activePair = clonePair(newest.activePair)
		initiatorCookie, _ := replacement.main.Cookies()
		replacement.activePair.InitiatorCookie = initiatorCookie
		replacement.activePair.ResponderCookie = cookie
		replacement.pairEstablished = newest.pairEstablished
		replacement.nextRekey = newest.nextRekey
		replacement.rekeyFailures = newest.rekeyFailures
		replacement.rekeyRetryAt = newest.rekeyRetryAt
	}
	c.debug("ike phase1 replacement established peer=%s predecessor_cookie=%x replacement_cookie=%x predecessors=%d", replacement.peerAddr, newestCookie, cookie, len(replacement.predecessors))
	if newest.activePair.Transform.Encryption == 0 {
		return events
	}
	return events
}

func samePeerIdentity(main *MainModeResponder, want Identification) bool {
	got, ok := main.PeerIdentity()
	return ok && got.IDType == want.IDType && got.ProtocolID == want.ProtocolID && got.Port == want.Port && bytes.Equal(got.Data, want.Data)
}

func removeCookie(cookies []Cookie, remove Cookie) []Cookie {
	for i, cookie := range cookies {
		if cookie == remove {
			return append(cookies[:i], cookies[i+1:]...)
		}
	}
	return cookies
}
func addressKey(peer net.Addr) string {
	if peer == nil {
		return ""
	}
	return peer.Network() + "\x00" + peer.String()
}

func addressPort(peer net.Addr) (netip.AddrPort, bool) {
	udp, ok := peer.(*net.UDPAddr)
	if !ok || udp == nil || udp.Port < 0 || udp.Port > 65535 {
		return netip.AddrPort{}, false
	}
	address, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(address.Unmap(), uint16(udp.Port)), true
}

func cloneNetAddr(peer net.Addr) net.Addr {
	switch value := peer.(type) {
	case *net.UDPAddr:
		return &net.UDPAddr{IP: append(net.IP(nil), value.IP...), Port: value.Port, Zone: value.Zone}
	case *net.IPAddr:
		return &net.IPAddr{IP: append(net.IP(nil), value.IP...), Zone: value.Zone}
	default:
		return peer
	}
}
