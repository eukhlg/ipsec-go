package server

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
)

type removeRecorder struct {
	mu     sync.Mutex
	events []RemoveEvent
}

// handler records events and touches the registry, which would deadlock if the
// registry invoked the handler while holding its lock.
func (r *removeRecorder) handler(registry *ESPRegistry) func(RemoveEvent) {
	return func(event RemoveEvent) {
		_ = registry.Count()
		r.mu.Lock()
		r.events = append(r.events, event)
		r.mu.Unlock()
	}
}

func (r *removeRecorder) snapshot() []RemoveEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RemoveEvent(nil), r.events...)
}

func withTimeout(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out: remove handler likely invoked under the registry lock")
	}
}

func clientSA(t *testing.T, pair isakmp.ESPPair) *esp.SA {
	t.Helper()
	sa, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey, Random: bytes.NewReader(bytes.Repeat([]byte{6}, 1<<16))})
	if err != nil {
		t.Fatal(err)
	}
	return sa
}

func installRecorded(t *testing.T, pairs ...isakmp.ESPPair) (*ESPRegistry, *removeRecorder, net.Addr) {
	t.Helper()
	registry := NewESPRegistry()
	recorder := &removeRecorder{}
	registry.SetRemoveHandler(recorder.handler(registry))
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}
	for _, pair := range pairs {
		if err := registry.Install(peer, pair); err != nil {
			t.Fatal(err)
		}
	}
	return registry, recorder, peer
}

func TestRemoveHandlerExplicitIKEAndClose(t *testing.T) {
	cookie := isakmp.Cookie{7}
	first := testESPPair(isakmp.EncapsulationNATTTransport)
	first.ResponderCookie = cookie
	second := testESPPair(isakmp.EncapsulationNATTTransport)
	second.ResponderCookie = cookie
	second.Inbound.SPI, second.Outbound.SPI = 0x33333333, 0x44444444
	third := testESPPair(isakmp.EncapsulationNATTTransport)
	third.Inbound.SPI, third.Outbound.SPI = 0x55555555, 0x66666666

	registry, recorder, peer := installRecorded(t, first, second, third)
	withTimeout(t, func() {
		registry.Remove(first.Outbound.SPI)
		registry.Remove(first.Inbound.SPI) // already gone: no second event
		registry.RemoveIKE(cookie)
		registry.Close()
	})
	events := recorder.snapshot()
	if len(events) != 3 {
		t.Fatalf("events=%+v", events)
	}
	want := []struct {
		reason RemoveReason
		spi    uint32
	}{{RemoveExplicit, first.Inbound.SPI}, {RemoveIKE, second.Inbound.SPI}, {RemoveClose, third.Inbound.SPI}}
	for i, w := range want {
		e := events[i]
		if e.Reason != w.reason || e.InboundSPI != w.spi || e.Direction != RemoveDirectionNone || e.Lifetime != nil {
			t.Fatalf("event %d=%+v, want reason=%s spi=%08x", i, e, w.reason, w.spi)
		}
		if e.Peer == nil || e.Peer.String() != peer.String() {
			t.Fatalf("event %d peer=%v", i, e.Peer)
		}
	}
	if events[1].IKECookie != cookie {
		t.Fatalf("ike cookie=%x", events[1].IKECookie)
	}
}

func TestRemoveHandlerSPIReuse(t *testing.T) {
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	registry, recorder, peer := installRecorded(t, pair)
	withTimeout(t, func() {
		if err := registry.Install(peer, pair); err != nil {
			t.Error(err)
		}
	})
	events := recorder.snapshot()
	if len(events) != 1 || events[0].Reason != RemoveSPIReuse || events[0].InboundSPI != pair.Inbound.SPI {
		t.Fatalf("events=%+v", events)
	}
	if registry.Count() != 1 {
		t.Fatalf("count=%d", registry.Count())
	}
}

func TestRemoveHandlerInboundByteLifetime(t *testing.T) {
	for _, phased := range []bool{false, true} {
		pair := testESPPair(isakmp.EncapsulationNATTTransport)
		pair.Transform.LifetimeKilobytes = 1
		registry, recorder, peer := installRecorded(t, pair)
		client := clientSA(t, pair)
		var lastErr error
		withTimeout(t, func() {
			for i := 0; i < 20 && lastErr == nil; i++ {
				wire, err := client.Seal(bytes.Repeat([]byte{1}, 200), esp.IPProtocolUDP)
				if err != nil {
					t.Error(err)
					return
				}
				if phased {
					p, err := registry.Precheck(peer, wire)
					if err != nil {
						lastErr = err
						break
					}
					p.Authenticate()
					_, _, _, lastErr = p.Commit()
				} else {
					_, _, _, lastErr = registry.OpenInPlace(peer, wire)
				}
			}
		})
		if !errors.Is(lastErr, esp.ErrSALifetime) {
			t.Fatalf("phased=%t last error=%v", phased, lastErr)
		}
		events := recorder.snapshot()
		if len(events) != 1 {
			t.Fatalf("phased=%t events=%+v", phased, events)
		}
		e := events[0]
		if e.Reason != RemoveLifetime || e.Direction != RemoveDirectionInbound || e.Lifetime == nil || e.Lifetime.Reason != esp.LifetimeBytes || e.Lifetime.Limit != 1024 || e.InboundSPI != pair.Inbound.SPI {
			t.Fatalf("phased=%t event=%+v lifetime=%+v", phased, e, e.Lifetime)
		}
		// The app's follow-up Remove after ErrSALifetime must not duplicate the event.
		registry.Remove(pair.Inbound.SPI)
		if n := len(recorder.snapshot()); n != 1 {
			t.Fatalf("phased=%t duplicate events=%d", phased, n)
		}
	}
}

func TestRemoveHandlerOutboundByteLifetime(t *testing.T) {
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	pair.Transform.LifetimeKilobytes = 1
	registry, recorder, peer := installRecorded(t, pair)
	client := clientSA(t, pair)
	wire, _ := client.Seal([]byte{1}, esp.IPProtocolUDP)
	association, _, _, err := registry.Open(peer, wire)
	if err != nil {
		t.Fatal(err)
	}
	var lastErr error
	withTimeout(t, func() {
		for i := 0; i < 20 && lastErr == nil; i++ {
			_, lastErr = registry.Seal(association, peer, bytes.Repeat([]byte{2}, 200), esp.IPProtocolUDP)
		}
	})
	if !errors.Is(lastErr, esp.ErrSALifetime) {
		t.Fatalf("last error=%v", lastErr)
	}
	events := recorder.snapshot()
	if len(events) != 1 || events[0].Direction != RemoveDirectionOutbound || events[0].Lifetime == nil || events[0].Lifetime.Reason != esp.LifetimeBytes {
		t.Fatalf("events=%+v", events)
	}
	if _, err := registry.Seal(association, peer, []byte{3}, esp.IPProtocolUDP); err != ErrUnknownESP {
		t.Fatalf("after removal: %v", err)
	}
}

func TestRemoveHandlerNilAndStrings(t *testing.T) {
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	registry := NewESPRegistry()
	registry.SetRemoveHandler(func(RemoveEvent) { t.Fatal("handler should be cleared") })
	registry.SetRemoveHandler(nil)
	if err := registry.Install(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 4500}, pair); err != nil {
		t.Fatal(err)
	}
	registry.Remove(pair.Inbound.SPI)
	for reason, want := range map[RemoveReason]string{RemoveExplicit: "explicit", RemoveIKE: "ike", RemoveSPIReuse: "spi-reuse", RemoveLifetime: "lifetime", RemoveClose: "close", 0: "unknown"} {
		if reason.String() != want {
			t.Fatalf("%d=%q", reason, reason.String())
		}
	}
	if RemoveDirectionInbound.String() != "inbound" || RemoveDirectionOutbound.String() != "outbound" || RemoveDirectionNone.String() != "none" {
		t.Fatal("direction strings")
	}
}
