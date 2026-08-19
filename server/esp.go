package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eukhlg/l2tp-go/protocol/esp"
	"github.com/eukhlg/l2tp-go/protocol/isakmp"
)

var (
	ErrUnknownESP = errors.New("esp server: unknown SPI")
	ErrESPPeer    = errors.New("esp server: peer mismatch")
	ErrNotL2TP    = errors.New("esp server: transport payload is not UDP/1701")
)

type espSession struct {
	peerIP                  net.IP
	peer                    net.Addr
	inbound, outbound       *esp.SA
	encapsulation           uint16
	inboundSPI, outboundSPI uint32
	ikeCookie               isakmp.Cookie
	revoked                 atomic.Bool
}

type ESPRegistry struct {
	mu      sync.RWMutex
	inbound map[uint32]*espSession
	bySPI   map[uint32]*espSession
	byIKE   map[isakmp.Cookie]map[*espSession]struct{}
	latest  map[isakmp.Cookie]*espSession
}

func NewESPRegistry() *ESPRegistry {
	return &ESPRegistry{inbound: make(map[uint32]*espSession), bySPI: make(map[uint32]*espSession), byIKE: make(map[isakmp.Cookie]map[*espSession]struct{}), latest: make(map[isakmp.Cookie]*espSession)}
}

func (r *ESPRegistry) Install(peer net.Addr, pair isakmp.ESPPair) error {
	ip := addressIP(peer)
	if ip == nil {
		return ErrESPPeer
	}
	lifetime := time.Duration(pair.Transform.LifetimeSeconds) * time.Second
	limits := esp.Limits{}
	if pair.Transform.LifetimeKilobytes != 0 {
		limits.Bytes = uint64(pair.Transform.LifetimeKilobytes) * 1024
	}
	inbound, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey, Lifetime: lifetime, Limits: limits})
	if err != nil {
		return err
	}
	outbound, err := esp.NewSA(esp.SAConfig{SPI: pair.Outbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Outbound.EncryptionKey, AuthenticationKey: pair.Outbound.AuthenticationKey, Lifetime: lifetime, Limits: limits})
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session := &espSession{peerIP: append(net.IP(nil), ip...), peer: peer, inbound: inbound, outbound: outbound, encapsulation: pair.Transform.Encapsulation, inboundSPI: pair.Inbound.SPI, outboundSPI: pair.Outbound.SPI, ikeCookie: pair.ResponderCookie}
	if old := r.bySPI[pair.Inbound.SPI]; old != nil {
		r.removeLocked(old)
	}
	if old := r.bySPI[pair.Outbound.SPI]; old != nil {
		r.removeLocked(old)
	}
	r.inbound[pair.Inbound.SPI] = session
	r.bySPI[pair.Inbound.SPI], r.bySPI[pair.Outbound.SPI] = session, session
	if pair.ResponderCookie != (isakmp.Cookie{}) {
		if r.byIKE[pair.ResponderCookie] == nil {
			r.byIKE[pair.ResponderCookie] = make(map[*espSession]struct{})
		}
		r.byIKE[pair.ResponderCookie][session] = struct{}{}
		r.latest[pair.ResponderCookie] = session
	}
	return nil
}

func (r *ESPRegistry) lookup(peer net.Addr, wire []byte) (*espSession, error) {
	if len(wire) < 4 {
		return nil, esp.ErrShortPacket
	}
	spi := binary.BigEndian.Uint32(wire[:4])
	r.mu.RLock()
	session := r.inbound[spi]
	r.mu.RUnlock()
	if session == nil {
		return nil, ErrUnknownESP
	}
	if session.revoked.Load() {
		return nil, ErrUnknownESP
	}
	if ip := addressIP(peer); ip == nil || !ip.Equal(session.peerIP) {
		return nil, ErrESPPeer
	}
	return session, nil
}

func (r *ESPRegistry) Remove(spi uint32) {
	r.mu.Lock()
	if session := r.bySPI[spi]; session != nil {
		r.removeLocked(session)
	}
	r.mu.Unlock()
}

func (r *ESPRegistry) RemoveIKE(cookie isakmp.Cookie) {
	r.mu.Lock()
	for session := range r.byIKE[cookie] {
		r.removeLocked(session)
	}
	delete(r.byIKE, cookie)
	r.mu.Unlock()
}

// RebindIKE transfers live child SAs to a replacement IKE SA without
// recreating their crypto state or disturbing flows that reference them.
func (r *ESPRegistry) RebindIKE(from, to isakmp.Cookie) {
	if from == to || from == (isakmp.Cookie{}) || to == (isakmp.Cookie{}) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	sessions := r.byIKE[from]
	if len(sessions) == 0 {
		return
	}
	if r.byIKE[to] == nil {
		r.byIKE[to] = make(map[*espSession]struct{})
	}
	latest := r.latest[from]
	for session := range sessions {
		delete(sessions, session)
		session.ikeCookie = to
		r.byIKE[to][session] = struct{}{}
	}
	delete(r.byIKE, from)
	delete(r.latest, from)
	if latest != nil && !latest.revoked.Load() {
		r.latest[to] = latest
	}
}

func (r *ESPRegistry) Close() {
	r.mu.Lock()
	for _, session := range r.inbound {
		session.revoked.Store(true)
	}
	r.inbound = make(map[uint32]*espSession)
	r.bySPI = make(map[uint32]*espSession)
	r.byIKE = make(map[isakmp.Cookie]map[*espSession]struct{})
	r.latest = make(map[isakmp.Cookie]*espSession)
	r.mu.Unlock()
}

func (r *ESPRegistry) removeLocked(session *espSession) {
	session.revoked.Store(true)
	delete(r.inbound, session.inboundSPI)
	delete(r.bySPI, session.inboundSPI)
	delete(r.bySPI, session.outboundSPI)
	if sessions := r.byIKE[session.ikeCookie]; sessions != nil {
		delete(sessions, session)
		if len(sessions) == 0 {
			delete(r.byIKE, session.ikeCookie)
			delete(r.latest, session.ikeCookie)
		} else if r.latest[session.ikeCookie] == session {
			// This is normally only reached when the newest SA itself expires.
			// Keep any overlapping SA usable until the peer completes another rekey.
			for replacement := range sessions {
				r.latest[session.ikeCookie] = replacement
				break
			}
		}
	}
}

// replacement returns the newest live child SA belonging to the same IKE SA.
// Quick Mode rekeying deliberately overlaps the old and new child SAs, so an
// L2TP flow may still point at the old SA when the peer deletes it.
func (r *ESPRegistry) replacement(session *espSession) *espSession {
	if session == nil || session.ikeCookie == (isakmp.Cookie{}) {
		return nil
	}
	r.mu.RLock()
	replacement := r.latest[session.ikeCookie]
	r.mu.RUnlock()
	if replacement == nil || replacement == session || replacement.revoked.Load() || !replacement.peerIP.Equal(session.peerIP) || replacement.encapsulation != session.encapsulation {
		return nil
	}
	return replacement
}
func (r *ESPRegistry) Count() int { r.mu.RLock(); defer r.mu.RUnlock(); return len(r.inbound) }

type ESPDatagram struct {
	Payload []byte
	Peer    net.Addr
	NATT    bool
}
type ESPBridgeResult struct {
	Datagrams []ESPDatagram
	L2TP      Result
}
type espFlow struct {
	session    *espSession
	peer       net.Addr
	clientPort uint16
}

type ESPBridge struct {
	Engine   *Engine
	Registry *ESPRegistry
	mu       sync.RWMutex
	flows    map[string]espFlow
	Tracef   func(string, ...any)
}

func NewESPBridge(engine *Engine, registry *ESPRegistry) (*ESPBridge, error) {
	if engine == nil || registry == nil {
		return nil, errors.New("esp server: engine and registry are required")
	}
	return &ESPBridge{Engine: engine, Registry: registry, flows: make(map[string]espFlow)}, nil
}

// Handle receives a bare ESP packet (raw protocol 50 or the UDP/4500 payload),
// authenticates it, and feeds its UDP/1701 body to the existing L2TP engine.
func (b *ESPBridge) Handle(peer net.Addr, wire []byte, now time.Time) (ESPBridgeResult, error) {
	session, err := b.Registry.lookup(peer, wire)
	if err != nil {
		return ESPBridgeResult{}, err
	}
	udp, next, err := session.inbound.Open(wire)
	if err != nil {
		if errors.Is(err, esp.ErrSALifetime) {
			b.Registry.Remove(session.inboundSPI)
		}
		return ESPBridgeResult{}, err
	}
	if next != esp.IPProtocolUDP {
		return ESPBridgeResult{}, ErrNotL2TP
	}
	sourcePort, destinationPort, payload, err := decodeUDP(udp)
	if err != nil || destinationPort != 1701 {
		return ESPBridgeResult{}, ErrNotL2TP
	}
	logicalPeer := &net.UDPAddr{IP: append(net.IP(nil), session.peerIP...), Port: int(sourcePort)}
	if b.Tracef != nil {
		b.Tracef("esp open peer=%s spi=%08x next_header=%d udp=%d->%d payload_bytes=%d encapsulation=%d", peer, session.inboundSPI, next, sourcePort, destinationPort, len(payload), session.encapsulation)
	}
	result, err := b.Engine.HandleDatagram(logicalPeer, payload, now)
	if err != nil {
		return ESPBridgeResult{}, err
	}
	b.mu.Lock()
	b.flows[logicalPeer.String()] = espFlow{session: session, peer: peer, clientPort: sourcePort}
	b.mu.Unlock()
	out := ESPBridgeResult{L2TP: result}
	for _, reply := range result.Replies {
		datagram, err := sealUDPReply(session, peer, sourcePort, reply)
		if err != nil {
			if errors.Is(err, esp.ErrSALifetime) {
				b.Registry.Remove(session.inboundSPI)
			}
			return ESPBridgeResult{}, err
		}
		out.Datagrams = append(out.Datagrams, datagram)
	}
	return out, nil
}

// SealL2TP encrypts an asynchronous L2TP payload, such as a packet returned
// from TUN routing, for a previously observed protected UDP flow.
func (b *ESPBridge) SealL2TP(peer net.Addr, payload []byte) (ESPDatagram, error) {
	b.mu.RLock()
	flow, ok := b.flows[peer.String()]
	b.mu.RUnlock()
	if !ok {
		return ESPDatagram{}, ErrESPPeer
	}
	datagram, err := sealUDPReply(flow.session, flow.peer, flow.clientPort, payload)
	if errors.Is(err, esp.ErrSALifetime) {
		b.Registry.Remove(flow.session.inboundSPI)
	}
	if errors.Is(err, ErrUnknownESP) || errors.Is(err, esp.ErrSALifetime) {
		if replacement := b.Registry.replacement(flow.session); replacement != nil {
			flow.session, flow.peer = replacement, replacement.peer
			b.mu.Lock()
			b.flows[peer.String()] = flow
			b.mu.Unlock()
			datagram, err = sealUDPReply(flow.session, flow.peer, flow.clientPort, payload)
		}
	}
	if errors.Is(err, esp.ErrSALifetime) && !flow.session.revoked.Load() {
		b.Registry.Remove(flow.session.inboundSPI)
	}
	return datagram, err
}

func sealUDPReply(session *espSession, peer net.Addr, clientPort uint16, payload []byte) (ESPDatagram, error) {
	if session.revoked.Load() {
		return ESPDatagram{}, ErrUnknownESP
	}
	udp := encodeUDP(1701, clientPort, payload)
	wire, err := session.outbound.Seal(udp, esp.IPProtocolUDP)
	if err != nil {
		return ESPDatagram{}, err
	}
	return ESPDatagram{Payload: wire, Peer: peer, NATT: session.encapsulation == isakmp.EncapsulationNATTTransport}, nil
}

func decodeUDP(wire []byte) (uint16, uint16, []byte, error) {
	if len(wire) < 8 {
		return 0, 0, nil, ErrNotL2TP
	}
	length := int(binary.BigEndian.Uint16(wire[4:6]))
	if length < 8 || length > len(wire) {
		return 0, 0, nil, ErrNotL2TP
	}
	return binary.BigEndian.Uint16(wire[:2]), binary.BigEndian.Uint16(wire[2:4]), append([]byte(nil), wire[8:length]...), nil
}
func encodeUDP(source, destination uint16, payload []byte) []byte {
	wire := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(wire[:2], source)
	binary.BigEndian.PutUint16(wire[2:4], destination)
	binary.BigEndian.PutUint16(wire[4:6], uint16(len(wire)))
	copy(wire[8:], payload)
	return wire
}

func addressIP(peer net.Addr) net.IP {
	switch value := peer.(type) {
	case *net.UDPAddr:
		return value.IP
	case *net.IPAddr:
		return value.IP
	}
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func (r *ESPRegistry) String() string { return fmt.Sprintf("ESPRegistry{%d}", r.Count()) }
