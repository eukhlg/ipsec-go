package isakmp

import (
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
	Phase1Lifetime    time.Duration
	HandshakeTimeout  time.Duration
	QuickModeTimeout  time.Duration
}

type ControlPlaneResult struct {
	Reply       []byte
	Established *ESPPair
}

type controlSA struct {
	peer          string
	peerIP        netip.Addr
	main          *MainModeResponder
	quick         map[uint32]*QuickModeResponder
	quickUpdated  map[uint32]time.Time
	responses     map[string][]byte
	responseOrder []string
	updated       time.Time
	expires       time.Time
}

type ControlPlane struct {
	mu     sync.Mutex
	config ControlPlaneConfig
	sas    map[Cookie]*controlSA
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
	if config.MaxPhase1SAs < 0 {
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
		return ControlPlaneResult{}, err
	}
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
		if len(c.sas) >= c.config.MaxPhase1SAs {
			return ControlPlaneResult{}, ErrSALimit
		}
		remoteEndpoint, ok := addressPort(peer)
		if c.config.ResponderEndpoint.IsValid() && !ok {
			return ControlPlaneResult{}, ErrUnknownSA
		}
		main, err := NewMainModeResponder(MainModeConfig{PreSharedKey: c.config.PreSharedKey, ResponderID: c.config.ResponderID, LocalEndpoint: c.config.ResponderEndpoint, RemoteEndpoint: remoteEndpoint, Random: c.config.Random})
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
		runtime := &controlSA{peer: addressKey(peer), peerIP: remoteEndpoint.Addr(), main: main, quick: make(map[uint32]*QuickModeResponder), quickUpdated: make(map[uint32]time.Time), responses: make(map[string][]byte), updated: now, expires: now.Add(lifetime)}
		runtime.cacheResponse(wire, reply)
		c.sas[responderCookie] = runtime
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
	}
	if reply, ok := sa.responses[string(wire)]; ok {
		if migratePeer {
			sa.peer = addressKey(peer)
		}
		return ControlPlaneResult{Reply: append([]byte(nil), reply...)}, nil
	}
	var reply []byte
	var established *ESPPair
	switch packet.Exchange {
	case ExchangeIdentityProtect:
		reply, err = sa.main.Handle(wire)
		if err != nil && sa.main.State() == MainModeFailed {
			sa.main.Close()
			delete(c.sas, packet.ResponderCookie)
		}
	case ExchangeQuickMode:
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
				established = &pair
				quick.Close()
				delete(sa.quick, packet.MessageID)
				delete(sa.quickUpdated, packet.MessageID)
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
	}
	sa.cacheResponse(wire, reply)
	sa.updated = now
	return ControlPlaneResult{Reply: append([]byte(nil), reply...), Established: established}, nil
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
		handshakeExpired := sa.main.State() != MainModeEstablished && now.Sub(sa.updated) >= c.config.HandshakeTimeout
		if handshakeExpired || !now.Before(sa.expires) {
			for _, quick := range sa.quick {
				quick.Close()
			}
			sa.main.Close()
			delete(c.sas, cookie)
		}
	}
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
