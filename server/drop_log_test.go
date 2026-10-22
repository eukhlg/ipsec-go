package server

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
)

func TestDropLimiterFirstSuppressFlush(t *testing.T) {
	now := time.Unix(100, 0)
	l := &dropLimiter{now: func() time.Time { return now }}
	peer := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4500}
	if ok, n := l.allow("esp drop", peer, ErrUnknownESP); !ok || n != 0 {
		t.Fatalf("first: %t %d", ok, n)
	}
	for i := 0; i < 7; i++ {
		now = now.Add(500 * time.Millisecond)
		if ok, _ := l.allow("esp drop", peer, ErrUnknownESP); ok {
			t.Fatalf("drop %d logged inside the interval", i)
		}
	}
	now = now.Add(dropLogInterval)
	if ok, n := l.allow("esp drop", peer, ErrUnknownESP); !ok || n != 7 {
		t.Fatalf("after interval: %t suppressed=%d, want 7", ok, n)
	}
	if ok, _ := l.allow("esp drop", peer, ErrUnknownESP); ok {
		t.Fatal("interval did not restart after flush")
	}
}

func TestDropLimiterKeys(t *testing.T) {
	now := time.Unix(100, 0)
	l := &dropLimiter{now: func() time.Time { return now }}
	a := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4500}
	aOtherPort := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 61000}
	b := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 4500}
	first := &esp.LifetimeError{Reason: esp.LifetimeBytes, Bytes: 10, Limit: 20}
	second := &esp.LifetimeError{Reason: esp.LifetimeBytes, Bytes: 11, Limit: 20}
	if ok, _ := l.allow("esp commit drop", a, first); !ok {
		t.Fatal("first lifetime drop not logged")
	}
	if ok, _ := l.allow("esp commit drop", aOtherPort, fmt.Errorf("wrapped: %w", second)); ok {
		t.Fatal("same peer IP and error kind must share a key regardless of port, counters or wrapping")
	}
	if ok, _ := l.allow("esp commit drop", b, first); !ok {
		t.Fatal("different peer must have its own key")
	}
	if ok, _ := l.allow("esp plaintext drop", a, first); !ok {
		t.Fatal("different drop kind must have its own key")
	}
	if ok, _ := l.allow("esp commit drop", a, esp.ErrReplay); !ok {
		t.Fatal("different error kind must have its own key")
	}
	if ok, _ := l.allow("esp commit drop", a, errors.New("custom")); !ok {
		t.Fatal("unclassified errors key by message")
	}
}

func TestDropLimiterBoundsMemory(t *testing.T) {
	l := &dropLimiter{}
	for i := 0; i < dropLogMaxKeys+10; i++ {
		l.allow("esp drop", &net.UDPAddr{IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), Port: 4500}, ErrUnknownESP)
	}
	if n := len(l.entries); n > dropLogMaxKeys {
		t.Fatalf("entries=%d exceeds cap %d", n, dropLogMaxKeys)
	}
}

func TestDebugDropFormatsSuppressedCount(t *testing.T) {
	now := time.Unix(100, 0)
	var lines []string
	s := &ESPTransportServer{Debugf: func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }}
	s.drops.now = func() time.Time { return now }
	peer := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4500}
	for i := 0; i < 3; i++ {
		s.debugDrop("esp drop", peer, ErrUnknownESP, "esp drop peer=%s error=%v", peer, ErrUnknownESP)
	}
	now = now.Add(dropLogInterval)
	s.debugDrop("esp drop", peer, ErrUnknownESP, "esp drop peer=%s error=%v", peer, ErrUnknownESP)
	if len(lines) != 2 || strings.Contains(lines[0], "suppressed") || !strings.HasSuffix(lines[1], "suppressed=2") {
		t.Fatalf("lines=%q", lines)
	}
	quiet := &ESPTransportServer{}
	quiet.debugDrop("esp drop", peer, ErrUnknownESP, "esp drop peer=%s error=%v", peer, ErrUnknownESP)
}
