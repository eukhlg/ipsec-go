package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

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
	revoked                 atomic.Bool
}

type ESPRegistry struct {
	mu      sync.RWMutex
	inbound map[uint32]*Association
	bySPI   map[uint32]*Association
	byIKE   map[isakmp.Cookie]map[*Association]struct{}
	latest  map[isakmp.Cookie]*Association
}

func NewESPRegistry() *ESPRegistry {
	return &ESPRegistry{inbound: make(map[uint32]*Association), bySPI: make(map[uint32]*Association), byIKE: make(map[isakmp.Cookie]map[*Association]struct{}), latest: make(map[isakmp.Cookie]*Association)}
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
	session := &Association{owner: r, peerIP: append(net.IP(nil), ip...), peer: peer, inbound: inbound, outbound: outbound, encapsulation: pair.Transform.Encapsulation, inboundSPI: pair.Inbound.SPI, outboundSPI: pair.Outbound.SPI, ikeCookie: pair.ResponderCookie}
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

// replacement returns the newest live child SA belonging to the same IKE SA.
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

func (r *ESPRegistry) Cookie(session *Association) isakmp.Cookie {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if session == nil {
		return isakmp.Cookie{}
	}
	return session.ikeCookie
}
func (s *Association) PeerIP() net.IP        { return append(net.IP(nil), s.peerIP...) }
func (s *Association) Peer() net.Addr        { return s.peer }
func (s *Association) InboundSPI() uint32    { return s.inboundSPI }
func (s *Association) Encapsulation() uint16 { return s.encapsulation }

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
