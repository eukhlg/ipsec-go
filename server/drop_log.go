package server

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
)

// dropLogInterval bounds repeated drop logs per peer and error kind.
const dropLogInterval = 5 * time.Second

// dropLogMaxKeys caps limiter memory when many peers or kinds appear.
const dropLogMaxKeys = 4096

type dropKey struct {
	kind string
	peer string
	err  string
}

type dropEntry struct {
	last       time.Time
	suppressed uint64
}

// dropLimiter rate-limits per-packet debug lines. The first drop for a key is
// logged immediately; later ones at most once per interval, reporting how many
// were suppressed since the previous line. The zero value is ready to use.
type dropLimiter struct {
	mu      sync.Mutex
	entries map[dropKey]*dropEntry
	now     func() time.Time // tests only
}

// allow reports whether to log this drop and how many identical drops were
// suppressed since the previous logged line for the same key.
func (l *dropLimiter) allow(kind string, peer net.Addr, err error) (bool, uint64) {
	key := dropKey{kind: kind, peer: peerHost(peer), err: dropErrorKind(err)}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	if l.entries == nil || len(l.entries) >= dropLogMaxKeys {
		l.entries = make(map[dropKey]*dropEntry)
	}
	entry := l.entries[key]
	if entry == nil {
		l.entries[key] = &dropEntry{last: now}
		return true, 0
	}
	if now.Sub(entry.last) < dropLogInterval {
		entry.suppressed++
		return false, 0
	}
	suppressed := entry.suppressed
	entry.last, entry.suppressed = now, 0
	return true, suppressed
}

// peerHost keys by address without the port: NAT may vary source ports.
func peerHost(peer net.Addr) string {
	if ip := addressIP(peer); ip != nil {
		return ip.String()
	}
	if peer == nil {
		return ""
	}
	return peer.String()
}

// dropErrorKind maps errors carrying per-packet details (such as lifetime
// counters) to a stable kind, so one condition shares one limiter key.
func dropErrorKind(err error) string {
	for _, sentinel := range []error{ErrUnknownESP, ErrESPPeer, esp.ErrSALifetime, esp.ErrReplay, esp.ErrAuthentication, esp.ErrInvalidPacket, esp.ErrShortPacket, esp.ErrSequenceExhausted} {
		if errors.Is(err, sentinel) {
			return sentinel.Error()
		}
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// debugDrop logs a rate-limited drop line. format must end with the error
// verb; a suppressed count is appended when earlier lines were withheld.
func (s *ESPTransportServer) debugDrop(kind string, peer net.Addr, err error, format string, args ...any) {
	if s.Debugf == nil {
		return
	}
	ok, suppressed := s.drops.allow(kind, peer, err)
	if !ok {
		return
	}
	if suppressed > 0 {
		format += " suppressed=%d"
		args = append(args, suppressed)
	}
	s.Debugf(format, args...)
}
