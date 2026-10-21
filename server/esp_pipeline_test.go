package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/eukhlg/ipsec-go/packetbuf"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// channelPacketConn provides a deterministic socket with deadline/close wakeups.
type channelPacketConn struct {
	packets chan []byte
	wake    chan struct{}
	once    sync.Once
}

func newPipelineConn(n int) *channelPacketConn {
	c := &channelPacketConn{packets: make(chan []byte, n), wake: make(chan struct{})}
	for i := 0; i < n; i++ {
		p := make([]byte, 100)
		binary.BigEndian.PutUint32(p, uint32(i+1))
		c.packets <- p
	}
	return c
}
func (c *channelPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.wake:
		return 0, nil, net.ErrClosed
	case b := <-c.packets:
		return copy(p, b), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}, nil
	}
}
func (c *channelPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *channelPacketConn) Close() error                              { c.once.Do(func() { close(c.wake) }); return nil }
func (c *channelPacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *channelPacketConn) SetDeadline(t time.Time) error             { return c.SetReadDeadline(t) }
func (c *channelPacketConn) SetReadDeadline(t time.Time) error {
	if time.Until(t) <= 0 {
		return c.Close()
	}
	return nil
}
func (c *channelPacketConn) SetWriteDeadline(time.Time) error { return nil }
func pipelineWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("pipeline did not progress")
	}
}

func TestESPPipelineFIFO(t *testing.T) {
	for _, natt := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "natt"}[natt], func(t *testing.T) {
			const n = 1000
			c := newPipelineConn(n)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var handled, delivered int
			var views [][]byte
			s := &ESPTransportServer{Conn: c, NATT: natt}
			s.HandlePacketInPlace = func(_ context.Context, _ net.Addr, wire []byte, _ time.Time) (ESPPacketResult, error) {
				handled++
				value := binary.BigEndian.Uint32(wire)
				views = append(views, wire)
				// Alternating SPI-like values exercise one FIFO across independent streams.
				return ESPPacketResult{Dispatch: func(context.Context) error {
					delivered++
					if value != uint32(delivered) || binary.BigEndian.Uint32(wire) != value {
						return errors.New("delivery reordered or storage reused")
					}
					if delivered == n {
						cancel()
					}
					return nil
				}}, nil
			}
			pool := newCountedPipelinePool(t)
			if err := s.serve(ctx, pool.acquire, pool.release); err != nil {
				t.Fatal(err)
			}
			pool.check()
			if handled != n || delivered != n {
				t.Fatalf("handled=%d delivered=%d", handled, delivered)
			}
			for _, v := range views {
				if !bytes.Equal(v, make([]byte, len(v))) {
					t.Fatal("plaintext not erased on release")
				}
			}
		})
	}
}

func TestESPPipelineBlockedShutdown(t *testing.T) {
	for _, stop := range []string{"cancel", "close", "dispatch-error"} {
		t.Run(stop, func(t *testing.T) {
			c := newPipelineConn(1000)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			running := make(chan struct{})
			unblock := make(chan struct{})
			full := make(chan struct{})
			done := make(chan struct{})
			var serveErr error
			var handled atomic.Int32
			var delivered atomic.Int32
			var views [][]byte
			terminal := errors.New("terminal dispatch")
			s := &ESPTransportServer{Conn: c}
			s.HandlePacketInPlace = func(_ context.Context, _ net.Addr, wire []byte, _ time.Time) (ESPPacketResult, error) {
				views = append(views, wire)
				if handled.Add(1) == ESPDeliveryCapacity+2 {
					close(full)
				}
				return ESPPacketResult{Dispatch: func(ctx context.Context) error {
					if delivered.Add(1) != 1 {
						return errors.New("callback ran after shutdown")
					}
					close(running)
					if stop == "dispatch-error" {
						<-unblock
						return terminal
					}
					<-ctx.Done()
					<-unblock
					return nil
				}}, nil
			}
			pool := newCountedPipelinePool(t)
			go func() { serveErr = s.serve(ctx, pool.acquire, pool.release); close(done) }()
			pipelineWait(t, running)
			pipelineWait(t, full)
			// One running, 64 queued, one blocked enqueue: stage 1 cannot advance.
			time.Sleep(20 * time.Millisecond)
			if got := handled.Load(); got != ESPDeliveryCapacity+2 {
				t.Fatalf("unbounded stage 1: %d", got)
			}
			switch stop {
			case "cancel":
				cancel()
			case "close":
				_ = s.Close()
			}
			if stop != "dispatch-error" {
				select {
				case <-done:
					t.Fatal("Serve returned with Dispatch still running")
				case <-time.After(20 * time.Millisecond):
				}
			}
			close(unblock)
			pipelineWait(t, done)
			if stop == "dispatch-error" && !errors.Is(serveErr, terminal) {
				t.Fatalf("error=%v", serveErr)
			}
			pool.check()
			if delivered.Load() != 1 {
				t.Fatalf("dispatch count=%d", delivered.Load())
			}
			for _, v := range views {
				if !bytes.Equal(v, make([]byte, len(v))) {
					t.Fatal("queued or in-flight plaintext not erased")
				}
			}
		})
	}
}

type countedPipelinePool struct {
	t                  *testing.T
	mu                 sync.Mutex
	owned              map[*packetbuf.Buffer]bool
	acquired, released int
}

func newCountedPipelinePool(t *testing.T) *countedPipelinePool {
	return &countedPipelinePool{t: t, owned: make(map[*packetbuf.Buffer]bool)}
}
func (p *countedPipelinePool) acquire(n int) (*packetbuf.Buffer, error) {
	b, err := packetbuf.Acquire(n)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.owned[b] {
		p.t.Error("buffer acquired while still owned")
	}
	p.owned[b] = true
	p.acquired++
	return b, nil
}
func (p *countedPipelinePool) release(b *packetbuf.Buffer) {
	p.mu.Lock()
	if !p.owned[b] {
		p.t.Error("buffer released without ownership")
	}
	delete(p.owned, b)
	p.released++
	p.mu.Unlock()
	b.Release()
}
func (p *countedPipelinePool) check() {
	p.t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.acquired != p.released || len(p.owned) != 0 {
		p.t.Fatalf("buffer leak: acquired=%d released=%d live=%d", p.acquired, p.released, len(p.owned))
	}
}

func TestESPPipelineNoDispatchRelease(t *testing.T) {
	c := newPipelineConn(100)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handled := 0
	s := &ESPTransportServer{Conn: c, HandlePacket: func(context.Context, net.Addr, []byte, time.Time) (ESPPacketResult, error) {
		handled++
		if handled == 100 {
			cancel()
		}
		if handled%2 == 0 {
			return ESPPacketResult{}, errors.New("rejected packet")
		}
		return ESPPacketResult{}, nil
	}}
	pool := newCountedPipelinePool(t)
	if err := s.serve(ctx, pool.acquire, pool.release); err != nil {
		t.Fatal(err)
	}
	pool.check()
	if handled != 100 {
		t.Fatal(handled)
	}
}

func TestESPPipelineBackpressureResumesWithoutLoss(t *testing.T) {
	const n = 300
	c := newPipelineConn(n)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	running, full, unblock, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var handled atomic.Int32
	var delivered int
	var serveErr error
	s := &ESPTransportServer{Conn: c, NATT: true}
	s.HandlePacketInPlace = func(_ context.Context, _ net.Addr, wire []byte, _ time.Time) (ESPPacketResult, error) {
		if handled.Add(1) == ESPDeliveryCapacity+2 {
			close(full)
		}
		value := binary.BigEndian.Uint32(wire)
		return ESPPacketResult{Dispatch: func(context.Context) error {
			if delivered == 0 {
				close(running)
				<-unblock
			}
			delivered++
			if value != uint32(delivered) || binary.BigEndian.Uint32(wire) != value {
				return errors.New("loss, reordering, or premature release")
			}
			if delivered == n {
				cancel()
			}
			return nil
		}}, nil
	}
	pool := newCountedPipelinePool(t)
	go func() { serveErr = s.serve(ctx, pool.acquire, pool.release); close(done) }()
	pipelineWait(t, running)
	pipelineWait(t, full)
	if handled.Load() != ESPDeliveryCapacity+2 {
		t.Fatal("backpressure did not bound the producer")
	}
	close(unblock)
	pipelineWait(t, done)
	if serveErr != nil || delivered != n {
		t.Fatalf("error=%v delivered=%d", serveErr, delivered)
	}
	pool.check()
}
