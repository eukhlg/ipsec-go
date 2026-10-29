package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	"github.com/eukhlg/netio/packetbuf"
	"github.com/eukhlg/netio/udptransport"
)

// Moved with ESPSender from the app; raw ESP writes go through senderConn
// directly, NAT-T writes through udptransport.Conn's single-message fallback.

func senderPair() isakmp.ESPPair {
	return isakmp.ESPPair{Transform: isakmp.ESPTransform{Encryption: isakmp.TransformESPAES, Authentication: isakmp.ESPAuthHMACSHA196, Encapsulation: isakmp.EncapsulationTransport, KeyBits: 128}, Inbound: isakmp.ESPDirectionalKeys{SPI: 0x11111111, EncryptionKey: bytes.Repeat([]byte{1}, 16), AuthenticationKey: bytes.Repeat([]byte{2}, 20)}, Outbound: isakmp.ESPDirectionalKeys{SPI: 0x22222222, EncryptionKey: bytes.Repeat([]byte{3}, 16), AuthenticationKey: bytes.Repeat([]byte{4}, 20)}}
}

func senderAssociation(t *testing.T, r *ESPRegistry, _ net.Addr, pair isakmp.ESPPair) *Association {
	t.Helper()
	r.mu.RLock()
	defer r.mu.RUnlock()
	association := r.inbound[pair.Inbound.SPI]
	if association == nil {
		t.Fatal("association not installed")
	}
	return association
}

func newTestESPSender(t *testing.T, ctx context.Context, raw, natt net.PacketConn, capacity int) *ESPSender {
	t.Helper()
	s, err := NewESPSender(ctx, raw, natt, capacity, udptransport.DefaultBatchSize, udptransport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type senderConn struct {
	started  chan struct{}
	finished chan struct{}
	unblock  chan struct{}
	closed   chan struct{}
	once     sync.Once
	result   error
	short    bool
	mu       sync.Mutex
	writes   [][]byte
}

func newSenderConn() *senderConn {
	return &senderConn{started: make(chan struct{}, 100), finished: make(chan struct{}, 100), unblock: make(chan struct{}), closed: make(chan struct{})}
}
func (c *senderConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.started <- struct{}{}
	defer func() { c.finished <- struct{}{} }()
	select {
	case <-c.unblock:
	case <-c.closed:
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	if c.result != nil {
		return 0, c.result
	}
	if c.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}
func (c *senderConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *senderConn) Close() error                           { c.once.Do(func() { close(c.closed) }); return nil }
func (c *senderConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (c *senderConn) SetDeadline(time.Time) error            { return nil }
func (c *senderConn) SetReadDeadline(time.Time) error        { return nil }
func (c *senderConn) SetWriteDeadline(time.Time) error       { return nil }
func waitSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}
func ownedDatagram(t *testing.T, peer net.Addr, value byte) (ESPDatagram, []byte) {
	t.Helper()
	b, err := packetbuf.Copy(bytes.Repeat([]byte{value}, 64))
	if err != nil {
		t.Fatal(err)
	}
	return ESPDatagram{Payload: b.Bytes(), Peer: peer, Buffer: b}, b.Bytes()
}
func assertErased(t *testing.T, views ...[]byte) {
	t.Helper()
	for _, v := range views {
		if !bytes.Equal(v, make([]byte, len(v))) {
			t.Fatal("owned packet not erased/released")
		}
	}
}

func TestESPSenderOwnershipShutdownAndFailedEnqueue(t *testing.T) {
	r := NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	if err := r.Install(peer, senderPair()); err != nil {
		t.Fatal(err)
	}
	association := senderAssociation(t, r, peer, senderPair())
	raw, natt := newSenderConn(), newSenderConn()
	sender := newTestESPSender(t, context.Background(), raw, natt, 1)
	first, a := ownedDatagram(t, peer, 1)
	second, b := ownedDatagram(t, peer, 2)
	third, c := ownedDatagram(t, peer, 3)
	if err := sender.Enqueue(association, first); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, raw.started)
	if err := sender.Enqueue(association, second); err != nil {
		t.Fatal(err)
	}
	failed := make(chan error, 1)
	go func() { failed <- sender.Enqueue(association, third) }()
	sender.Close()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("enqueue unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("producer stuck")
	}
	assertErased(t, a, b)
	if c[0] != 3 {
		t.Fatal("failed enqueue stole caller ownership")
	}
	third.Release()
	assertErased(t, c)
}

func TestESPSenderWriteErrorsReleaseActiveAndBacklog(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "short"}[short], func(t *testing.T) {
			r := NewESPRegistry()
			defer r.Close()
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			if err := r.Install(peer, senderPair()); err != nil {
				t.Fatal(err)
			}
			association := senderAssociation(t, r, peer, senderPair())
			raw, natt := newSenderConn(), newSenderConn()
			raw.short = short
			if !short {
				raw.result = errors.New("write failed")
			}
			sender := newTestESPSender(t, context.Background(), raw, natt, 1)
			first, a := ownedDatagram(t, peer, 1)
			second, b := ownedDatagram(t, peer, 2)
			if err := sender.Enqueue(association, first); err != nil {
				t.Fatal(err)
			}
			waitSignal(t, raw.started)
			if err := sender.Enqueue(association, second); err != nil {
				t.Fatal(err)
			}
			close(raw.unblock)
			select {
			case err := <-sender.Done():
				if err == nil {
					t.Fatal("missing write error")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("sender stuck")
			}
			sender.Close()
			assertErased(t, a, b)
		})
	}
}

func TestESPSenderFIFOAndRevocationRelease(t *testing.T) {
	r := NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	if err := r.Install(peer, senderPair()); err != nil {
		t.Fatal(err)
	}
	association := senderAssociation(t, r, peer, senderPair())
	raw, natt := newSenderConn(), newSenderConn()
	sender := newTestESPSender(t, context.Background(), raw, natt, 4)
	var views [][]byte
	for i := byte(1); i <= 3; i++ {
		d, v := ownedDatagram(t, peer, i)
		views = append(views, v)
		if err := sender.Enqueue(association, d); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			waitSignal(t, raw.started)
		}
	}
	close(raw.unblock)
	// A barrier packet blocks after all previous writes and releases complete.
	waitSignal(t, raw.finished)
	waitSignal(t, raw.finished)
	waitSignal(t, raw.finished)
	sender.Close()
	assertErased(t, views...)
	raw.mu.Lock()
	defer raw.mu.Unlock()
	if len(raw.writes) != 3 {
		t.Fatalf("writes=%d", len(raw.writes))
	}
	for i, p := range raw.writes {
		if p[0] != byte(i+1) {
			t.Fatal("packet ordering changed")
		}
	}
	// Revoked association rejection retains ownership with the producer.
	r.Remove(association.inboundSPI)
	d, v := ownedDatagram(t, peer, 9)
	if err := sender.Enqueue(association, d); err == nil {
		t.Fatal("accepted after shutdown")
	}
	if v[0] != 9 {
		t.Fatal("rejected buffer released")
	}
	d.Release()
}

func TestESPSenderRevokedQueuedPacket(t *testing.T) {
	r := NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	pair := senderPair()
	if err := r.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	association := senderAssociation(t, r, peer, pair)
	replacement := pair
	replacement.Inbound.SPI++
	replacement.Outbound.SPI++
	if err := r.Install(peer, replacement); err != nil {
		t.Fatal(err)
	}
	other := senderAssociation(t, r, peer, replacement)
	raw, natt := newSenderConn(), newSenderConn()
	sender := newTestESPSender(t, context.Background(), raw, natt, 4)
	first, a := ownedDatagram(t, peer, 1)
	revoked, b := ownedDatagram(t, peer, 2)
	barrier, c := ownedDatagram(t, peer, 3)
	if err := sender.Enqueue(other, first); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, raw.started)
	if err := sender.Enqueue(association, revoked); err != nil {
		t.Fatal(err)
	}
	r.Remove(association.inboundSPI)
	rejected, d := ownedDatagram(t, peer, 4)
	if err := sender.Enqueue(association, rejected); !errors.Is(err, ErrUnknownESP) {
		t.Fatal(err)
	}
	if d[0] != 4 {
		t.Fatal("rejection stole buffer")
	}
	rejected.Release()
	if err := sender.Enqueue(other, barrier); err != nil {
		t.Fatal(err)
	}
	close(raw.unblock)
	waitSignal(t, raw.finished)
	waitSignal(t, raw.finished)
	sender.Close()
	assertErased(t, a, b, c, d)
	raw.mu.Lock()
	defer raw.mu.Unlock()
	if len(raw.writes) != 2 || raw.writes[0][0] != 1 || raw.writes[1][0] != 3 {
		t.Fatal("revoked packet was transmitted")
	}
}

func TestESPSenderParentCancellationReleases(t *testing.T) {
	r := NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	pair := senderPair()
	if err := r.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	association := senderAssociation(t, r, peer, pair)
	ctx, cancel := context.WithCancel(context.Background())
	raw, natt := newSenderConn(), newSenderConn()
	sender := newTestESPSender(t, ctx, raw, natt, 1)
	d, a := ownedDatagram(t, peer, 1)
	if err := sender.Enqueue(association, d); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, raw.started)
	d, b := ownedDatagram(t, peer, 2)
	if err := sender.Enqueue(association, d); err != nil {
		t.Fatal(err)
	}
	cancel()
	sender.Close()
	assertErased(t, a, b)
	if err := <-sender.Done(); err != nil {
		t.Fatalf("normal cancellation: %v", err)
	}
}

type batchWriteFunc func([]udptransport.Message) (int, error)

func (f batchWriteFunc) Write(m []udptransport.Message) (int, error) { return f(m) }
func TestESPSenderBatchesPartialAndTerminal(t *testing.T) {
	for _, batchSize := range []int{1, 32, 128} {
		t.Run(fmt.Sprint(batchSize), func(t *testing.T) {
			for _, mode := range []string{"partial", "error", "zero", "cancel", "revoke"} {
				t.Run(mode, func(t *testing.T) {
					r := NewESPRegistry()
					defer r.Close()
					peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
					pair := senderPair()
					if err := r.Install(peer, pair); err != nil {
						t.Fatal(err)
					}
					sa := senderAssociation(t, r, peer, pair)
					raw, natt := newSenderConn(), newSenderConn()
					started, unblock := make(chan struct{}), make(chan struct{})
					calls := make(chan []byte, 10)
					attempt := 0
					writer := batchWriteFunc(func(m []udptransport.Message) (int, error) {
						attempt++
						if attempt == 1 {
							close(started)
							select {
							case <-unblock:
							case <-natt.closed:
								return 0, net.ErrClosed
							}
						}
						values := []byte{}
						for _, v := range m {
							values = append(values, v.Payload[0])
							if v.Peer != peer {
								t.Error("destination lost")
							}
						}
						calls <- values
						if attempt == 2 {
							switch mode {
							case "error":
								return 1, io.ErrClosedPipe
							case "zero":
								return 0, nil
							}
						}
						return 1, nil
					})
					s, err := NewESPSenderWithWriter(context.Background(), raw, natt, writer, 8, batchSize)
					if err != nil {
						t.Fatal(err)
					}
					views := [][]byte{}
					for i := byte(1); i <= 4; i++ {
						d, v := ownedDatagram(t, peer, i)
						d.NATT = true
						views = append(views, v)
						if err := s.Enqueue(sa, d); err != nil {
							t.Fatal(err)
						}
						if i == 1 {
							waitSignal(t, started)
						}
					}
					if mode == "cancel" {
						s.Close()
						assertErased(t, views...)
						return
					}
					if mode == "revoke" {
						r.Remove(sa.inboundSPI)
					}
					close(unblock)
					first := <-calls
					if len(first) != 1 || first[0] != 1 {
						t.Fatal(first)
					}
					if mode == "revoke" {
						s.Close()
						assertErased(t, views...)
						return
					}
					second := <-calls
					if len(second) != min(3, batchSize) || second[0] != 2 || second[len(second)-1] != byte(1+len(second)) {
						t.Fatalf("did not drain queued datagrams: %v", second)
					}
					if mode == "partial" {
						third, fourth := <-calls, <-calls
						if len(third) != min(2, batchSize) || third[0] != 3 || len(fourth) != 1 || fourth[0] != 4 {
							t.Fatalf("retry duplicated or reordered: %v %v", third, fourth)
						}
					} else {
						select {
						case err := <-s.Done():
							if err == nil {
								t.Fatal("missing terminal error")
							}
							if mode == "error" && !errors.Is(err, io.ErrClosedPipe) {
								t.Fatal(err)
							}
						case <-time.After(3 * time.Second):
							t.Fatal("busy loop or stuck")
						}
					}
					s.Close()
					assertErased(t, views...)
				})
			}
		})
	}
}

// A failure of either transport stops both and closes both sockets.
func TestESPSenderFailureStopsBothTransports(t *testing.T) {
	r := NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	if err := r.Install(peer, senderPair()); err != nil {
		t.Fatal(err)
	}
	association := senderAssociation(t, r, peer, senderPair())
	raw, natt := newSenderConn(), newSenderConn()
	failure := errors.New("natt failed")
	writer := batchWriteFunc(func([]udptransport.Message) (int, error) { return 0, failure })
	s, err := NewESPSenderWithWriter(context.Background(), raw, natt, writer, 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	d, v := ownedDatagram(t, peer, 1)
	d.NATT = true
	if err := s.Enqueue(association, d); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-s.Done():
		if !errors.Is(err, failure) {
			t.Fatalf("Done = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sender did not stop")
	}
	waitSignal(t, raw.closed)
	waitSignal(t, natt.closed)
	assertErased(t, v)
	rawPacket, w := ownedDatagram(t, peer, 2)
	if err := s.Enqueue(association, rawPacket); err == nil {
		t.Fatal("raw transport accepted after the NAT-T failure")
	}
	if w[0] != 2 {
		t.Fatal("rejected buffer released")
	}
	rawPacket.Release()
	s.Close()
}

// Steady-state NAT-T enqueue and send allocate nothing per packet.
func TestESPSenderEnqueueDoesNotAllocate(t *testing.T) {
	r := NewESPRegistry()
	defer r.Close()
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	if err := r.Install(peer, senderPair()); err != nil {
		t.Fatal(err)
	}
	association := senderAssociation(t, r, peer, senderPair())
	written := make(chan struct{}, 1)
	writer := batchWriteFunc(func(m []udptransport.Message) (int, error) { written <- struct{}{}; return len(m), nil })
	s, err := NewESPSenderWithWriter(context.Background(), newSenderConn(), newSenderConn(), writer, 4, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	buffer, err := packetbuf.Copy(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	defer buffer.Release()
	// Without a Buffer the datagram has no owner, so Enqueue and the send are
	// measured, not the pool.
	send := func() {
		d := ESPDatagram{Payload: buffer.Bytes(), Peer: peer, NATT: true}
		if err := s.Enqueue(association, d); err != nil {
			t.Fatal(err)
		}
		<-written
	}
	send()
	if allocs := testing.AllocsPerRun(200, send); allocs > 0 {
		t.Fatalf("enqueue and send allocate %v per packet", allocs)
	}
}
