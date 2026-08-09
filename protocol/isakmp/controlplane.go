package isakmp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var (
	ErrUnknownSA = errors.New("isakmp: unknown security association")
	ErrSALimit   = errors.New("isakmp: security association limit reached")
)

type ControlPlaneConfig struct {
	PreSharedKey   []byte
	ResponderID    Identification
	Random         io.Reader
	MaxPhase1SAs   int
	Phase1Lifetime time.Duration
}

type ControlPlaneResult struct {
	Reply       []byte
	Established *ESPPair
}

type controlSA struct {
	peer                   string
	main                   *MainModeResponder
	quick                  map[uint32]*QuickModeResponder
	lastRequest, lastReply []byte
	updated                time.Time
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
	if config.MaxPhase1SAs == 0 {
		config.MaxPhase1SAs = 1024
	}
	if config.MaxPhase1SAs < 0 {
		return nil, ErrInvalidCryptoInput
	}
	if config.Phase1Lifetime == 0 {
		config.Phase1Lifetime = 8 * time.Hour
	}
	return &ControlPlane{config: config, sas: make(map[Cookie]*controlSA)}, nil
}

func (c *ControlPlane) HandleDatagram(peer net.Addr, wire []byte, now time.Time) (ControlPlaneResult, error) {
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
			if existing.peer == addressKey(peer) && initiatorCookie == packet.InitiatorCookie && bytes.Equal(existing.lastRequest, wire) {
				return ControlPlaneResult{Reply: append([]byte(nil), existing.lastReply...)}, nil
			}
		}
		if len(c.sas) >= c.config.MaxPhase1SAs {
			return ControlPlaneResult{}, ErrSALimit
		}
		main, err := NewMainModeResponder(MainModeConfig{PreSharedKey: c.config.PreSharedKey, ResponderID: c.config.ResponderID, Random: c.config.Random})
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
		c.sas[responderCookie] = &controlSA{peer: addressKey(peer), main: main, quick: make(map[uint32]*QuickModeResponder), lastRequest: append([]byte(nil), wire...), lastReply: append([]byte(nil), reply...), updated: now}
		return ControlPlaneResult{Reply: reply}, nil
	}
	sa := c.sas[packet.ResponderCookie]
	if sa == nil || sa.peer != addressKey(peer) {
		return ControlPlaneResult{}, ErrUnknownSA
	}
	if bytes.Equal(sa.lastRequest, wire) {
		return ControlPlaneResult{Reply: append([]byte(nil), sa.lastReply...)}, nil
	}
	var reply []byte
	var established *ESPPair
	switch packet.Exchange {
	case ExchangeIdentityProtect:
		reply, err = sa.main.Handle(wire)
	case ExchangeQuickMode:
		quick := sa.quick[packet.MessageID]
		if quick == nil {
			quick, err = sa.main.NewQuickModeResponder(c.config.Random)
			if err == nil {
				sa.quick[packet.MessageID] = quick
			}
		}
		if err == nil {
			reply, err = quick.Handle(wire)
		}
		if err == nil {
			if pair, ok := quick.Pair(); ok {
				established = &pair
				delete(sa.quick, packet.MessageID)
			}
		}
	default:
		err = ErrUnexpectedExchange
	}
	if err != nil {
		return ControlPlaneResult{}, err
	}
	sa.lastRequest, sa.lastReply, sa.updated = append(sa.lastRequest[:0], wire...), append(sa.lastReply[:0], reply...), now
	return ControlPlaneResult{Reply: append([]byte(nil), reply...), Established: established}, nil
}

func (c *ControlPlane) expire(now time.Time) {
	for cookie, sa := range c.sas {
		if now.Sub(sa.updated) >= c.config.Phase1Lifetime {
			delete(c.sas, cookie)
		}
	}
}

func (c *ControlPlane) SACount() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.sas) }
func addressKey(peer net.Addr) string {
	if peer == nil {
		return ""
	}
	return peer.Network() + "\x00" + peer.String()
}
