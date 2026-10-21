package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eukhlg/ipsec-go/packetbuf"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
)

var (
	ErrUnknownESP = errors.New("esp server: unknown SPI")
	ErrESPPeer    = errors.New("esp server: peer mismatch")
)

// Association is an opaque pair of inbound and outbound ESP security associations.
// Obtain one from ESPRegistry.Open; the zero value cannot protect packets.
type Association struct {
	owner                   *ESPRegistry
	peerIP                  net.IP
	peer                    net.Addr
	inbound, outbound       *esp.SA
	encapsulation           uint16
	inboundSPI, outboundSPI uint32
	ikeCookie               isakmp.Cookie
	expiresAt               time.Time
	revoked                 atomic.Bool
}

// DefaultInboundReplayWindowSize tolerates burst reordering on fast VPN links.
const DefaultInboundReplayWindowSize = 1024

type ESPRegistryConfig struct {
	// ReplayWindowSize is a multiple of 64 from 64 through 1024. Zero selects
	// DefaultInboundReplayWindowSize. The value applies to all installed SAs.
	ReplayWindowSize uint32
}

type ESPRegistry struct {
	replayWindowSize uint32
	mu               sync.RWMutex
	inbound          map[uint32]*Association
	bySPI            map[uint32]*Association
	byIKE            map[isakmp.Cookie]map[*Association]struct{}
	latest           map[isakmp.Cookie]*Association
}

func NewESPRegistry() *ESPRegistry {
	return newESPRegistry(DefaultInboundReplayWindowSize)
}

// NewESPRegistryWithConfig validates receiver policy before any SA is installed.
// Configuration is immutable for the lifetime of the registry.
func NewESPRegistryWithConfig(config ESPRegistryConfig) (*ESPRegistry, error) {
	size := config.ReplayWindowSize
	if size == 0 {
		size = DefaultInboundReplayWindowSize
	}
	if _, err := esp.NewReplayWindow(size); err != nil {
		return nil, fmt.Errorf("esp registry: invalid replay window size %d: %w", size, err)
	}
	return newESPRegistry(size), nil
}

func newESPRegistry(size uint32) *ESPRegistry {
	return &ESPRegistry{replayWindowSize: size, inbound: make(map[uint32]*Association), bySPI: make(map[uint32]*Association), byIKE: make(map[isakmp.Cookie]map[*Association]struct{}), latest: make(map[isakmp.Cookie]*Association)}
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
	inbound, err := esp.NewSA(esp.SAConfig{ReplayWindowSize: r.replayWindowSize, SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey, Lifetime: lifetime, Limits: limits})
	if err != nil {
		return err
	}
	outbound, err := esp.NewSA(esp.SAConfig{SPI: pair.Outbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Outbound.EncryptionKey, AuthenticationKey: pair.Outbound.AuthenticationKey, Lifetime: lifetime, Limits: limits})
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session := &Association{owner: r, peerIP: append(net.IP(nil), ip...), peer: clonePeer(peer), inbound: inbound, outbound: outbound, encapsulation: pair.Transform.Encapsulation, inboundSPI: pair.Inbound.SPI, outboundSPI: pair.Outbound.SPI, ikeCookie: pair.ResponderCookie}
	if lifetime > 0 {
		session.expiresAt = time.Now().Add(lifetime)
	}
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
			r.byIKE[pair.ResponderCookie] = make(map[*Association]struct{})
		}
		r.byIKE[pair.ResponderCookie][session] = struct{}{}
		r.latest[pair.ResponderCookie] = session
	}
	return nil
}

func (r *ESPRegistry) lookup(peer net.Addr, wire []byte) (*Association, error) {
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
		r.byIKE[to] = make(map[*Association]struct{})
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
	r.inbound = make(map[uint32]*Association)
	r.bySPI = make(map[uint32]*Association)
	r.byIKE = make(map[isakmp.Cookie]map[*Association]struct{})
	r.latest = make(map[isakmp.Cookie]*Association)
	r.mu.Unlock()
}

func (r *ESPRegistry) removeLocked(session *Association) {
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

// Replacement returns the newest live child SA belonging to the same IKE SA.
// Quick Mode rekeying deliberately overlaps the old and new child SAs, so an
// L2TP flow may still point at the old SA when the peer deletes it.
func (r *ESPRegistry) Replacement(session *Association) *Association {
	if session == nil || session.owner != r {
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

func (r *ESPRegistry) BelongsToIKE(session *Association, cookie isakmp.Cookie) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return session != nil && session.owner == r && session.ikeCookie == cookie
}

func (r *ESPRegistry) Count() int { r.mu.RLock(); defer r.mu.RUnlock(); return len(r.inbound) }

type ESPDatagram struct {
	Payload []byte
	Peer    net.Addr
	NATT    bool
	// Buffer, when non-nil, owns Payload. The recipient must release it once
	// after its final use. Legacy Seal returns independent non-pooled Payload.
	Buffer *packetbuf.Buffer
}

// Release relinquishes owned pooled storage; legacy datagrams need no release.
func (d ESPDatagram) Release() {
	if d.Buffer != nil {
		d.Buffer.Release()
	}
}

// Open authenticates and decrypts an ESP packet, preserving association identity.
// The returned association is opaque and can be retained for replies and rekeying.
func (r *ESPRegistry) Open(peer net.Addr, wire []byte) (*Association, []byte, uint8, error) {
	session, err := r.lookup(peer, wire)
	if err != nil {
		return nil, nil, 0, err
	}
	payload, next, err := session.inbound.Open(wire)
	if errors.Is(err, esp.ErrSALifetime) {
		r.Remove(session.inboundSPI)
	}
	if err != nil {
		return nil, nil, 0, err
	}
	return session, payload, next, nil
}

// Seal protects a reply through a retained association. Revoked associations fail
// explicitly; callers can request Replacement to move an existing flow after rekeying.
func (r *ESPRegistry) Seal(session *Association, peer net.Addr, payload []byte, next uint8) (ESPDatagram, error) {
	if session == nil || session.owner != r || session.revoked.Load() {
		return ESPDatagram{}, ErrUnknownESP
	}
	wire, err := session.outbound.Seal(payload, next)
	if errors.Is(err, esp.ErrSALifetime) {
		r.Remove(session.inboundSPI)
	}
	if err != nil {
		return ESPDatagram{}, err
	}
	return ESPDatagram{Payload: wire, Peer: peer, NATT: session.encapsulation == isakmp.EncapsulationNATTTransport}, nil
}

// OpenInPlace borrows and mutates wire; the payload aliases its storage.
func (r *ESPRegistry) OpenInPlace(peer net.Addr, wire []byte) (*Association, []byte, uint8, error) {
	session, err := r.lookup(peer, wire)
	if err != nil {
		return nil, nil, 0, err
	}
	payload, next, err := session.inbound.OpenInPlace(wire)
	if errors.Is(err, esp.ErrSALifetime) {
		r.Remove(session.inboundSPI)
	}
	if err != nil {
		return nil, nil, 0, err
	}
	return session, payload, next, nil
}

// SealBuffer keeps ownership with the caller on error and returns a datagram
// owning buffer on success. No payload storage is allocated or copied.
func (r *ESPRegistry) SealBuffer(session *Association, peer net.Addr, buffer *packetbuf.Buffer, next uint8) (ESPDatagram, error) {
	if session == nil || session.owner != r || session.revoked.Load() {
		return ESPDatagram{}, ErrUnknownESP
	}
	err := session.outbound.SealBuffer(buffer, next)
	if errors.Is(err, esp.ErrSALifetime) {
		r.Remove(session.inboundSPI)
	}
	if err != nil {
		return ESPDatagram{}, err
	}
	return ESPDatagram{Payload: buffer.Bytes(), Peer: peer, NATT: session.encapsulation == isakmp.EncapsulationNATTTransport, Buffer: buffer}, nil
}

func (r *ESPRegistry) Cookie(session *Association) isakmp.Cookie {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if session == nil || session.owner != r {
		return isakmp.Cookie{}
	}
	return session.ikeCookie
}
func (s *Association) PeerIP() net.IP        { return append(net.IP(nil), s.peerIP...) }
func (s *Association) Peer() net.Addr        { return clonePeer(s.peer) }
func (s *Association) InboundSPI() uint32    { return s.inboundSPI }
func (s *Association) Encapsulation() uint16 { return s.encapsulation }

// clonePeer keeps mutable standard-library address values outside the registry.
func clonePeer(peer net.Addr) net.Addr {
	switch value := peer.(type) {
	case *net.UDPAddr:
		if value == nil {
			return nil
		}
		return &net.UDPAddr{IP: append(net.IP(nil), value.IP...), Port: value.Port, Zone: value.Zone}
	case *net.IPAddr:
		if value == nil {
			return nil
		}
		return &net.IPAddr{IP: append(net.IP(nil), value.IP...), Zone: value.Zone}
	default:
		return peer
	}
}

func addressIP(peer net.Addr) net.IP {
	if peer == nil {
		return nil
	}
	switch value := peer.(type) {
	case *net.UDPAddr:
		if value == nil {
			return nil
		}
		return value.IP
	case *net.IPAddr:
		if value == nil {
			return nil
		}
		return value.IP
	}
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func (r *ESPRegistry) String() string { return fmt.Sprintf("ESPRegistry{%d}", r.Count()) }

// Active reports whether encrypted packets retained for asynchronous sending may
// still use this association. Revocation and time expiry invalidate queued
// packets. A write already in progress may complete concurrently with removal.
func (s *Association) Active() bool {
	return s != nil && s.owner != nil && !s.revoked.Load() && (s.expiresAt.IsZero() || time.Now().Before(s.expiresAt))
}

// ReplayState snapshots receive state for diagnostics after Open rejects a
// packet. The snapshot may reflect subsequent traffic and is not authentication.
func (r *ESPRegistry) ReplayState(peer net.Addr, wire []byte) (esp.ReplayState, bool) {
	if len(wire) < 8 {
		return esp.ReplayState{}, false
	}
	session, err := r.lookup(peer, wire)
	if err != nil {
		return esp.ReplayState{}, false
	}
	return session.inbound.ReplayState(binary.BigEndian.Uint32(wire[4:8])), true
}
