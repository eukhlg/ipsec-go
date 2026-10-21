package udptransport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type senderSocket struct {
	closed chan struct{}
	once   sync.Once
}

func newSenderSocket() *senderSocket                              { return &senderSocket{closed: make(chan struct{})} }
func (c *senderSocket) Close() error                              { c.once.Do(func() { close(c.closed) }); return nil }
func (c *senderSocket) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, io.EOF }
func (c *senderSocket) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c *senderSocket) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *senderSocket) SetDeadline(time.Time) error               { return nil }
func (c *senderSocket) SetReadDeadline(time.Time) error           { return nil }
func (c *senderSocket) SetWriteDeadline(time.Time) error          { return nil }

type testOwner struct {
	data     []byte
	released atomic.Int32
}

func (o *testOwner) Release() {
	if o.released.Add(1) != 1 {
		panic("double release")
	}
	clear(o.data)
}

type senderWriter func([]Message) (int, error)

func (f senderWriter) Write(m []Message) (int, error) { return f(m) }
func waitSender(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("sender stuck")
	}
}

func TestSenderBatchFIFOAndMixedDestinations(t *testing.T) {
	socket := newSenderSocket()
	started, unblock := make(chan struct{}), make(chan struct{})
	peers := []net.Addr{&net.UDPAddr{Port: 1701}, &net.UDPAddr{Port: 1702}}
	var seen []int
	var sizes []int
	calls := 0
	writer := senderWriter(func(m []Message) (int, error) {
		calls++
		if calls == 1 {
			close(started)
			select {
			case <-unblock:
			case <-socket.closed:
				return 0, net.ErrClosed
			}
		}
		sizes = append(sizes, len(m))
		n := min(2, len(m))
		for _, p := range m[:n] {
			v := int(p.Payload[0])
			if p.Peer != peers[v%2] {
				t.Error("destination changed")
			}
			seen = append(seen, v)
		}
		return n, nil
	})
	sender, _ := NewSenderWithWriter(context.Background(), socket, writer, 8)
	defer sender.Close()
	var owners []*testOwner
	for i := 0; i < 7; i++ {
		o := &testOwner{data: []byte{byte(i)}}
		owners = append(owners, o)
		if err := sender.Enqueue(context.Background(), Datagram{Payload: o.data, Peer: peers[i%2], Owner: o}); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			waitSender(t, started)
		}
	}
	close(unblock)
	if err := sender.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 7 {
		t.Fatal(seen)
	}
	for i, v := range seen {
		if v != i {
			t.Fatal("duplicate or reordered", seen)
		}
	}
	if len(sizes) < 2 || sizes[1] < 6 {
		t.Fatal("did not drain immediately available batch", sizes)
	}
	for _, o := range owners {
		if o.released.Load() != 1 {
			t.Fatal("flush did not release completed ownership")
		}
	}
}
func TestSenderTerminalErrorsAndShutdown(t *testing.T) {
	for _, mode := range []string{"error", "prefix-error", "zero", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			socket := newSenderSocket()
			started, unblock := make(chan struct{}), make(chan struct{})
			calls := 0
			writer := senderWriter(func(m []Message) (int, error) {
				calls++
				if calls == 1 {
					close(started)
					select {
					case <-unblock:
					case <-socket.closed:
						return 0, net.ErrClosed
					}
				}
				switch mode {
				case "zero":
					return 0, nil
				case "prefix-error":
					return 1, io.ErrClosedPipe
				default:
					return 0, io.ErrClosedPipe
				}
			})
			sender, _ := NewSenderWithWriter(context.Background(), socket, writer, 1)
			a, b, c := &testOwner{data: []byte{1}}, &testOwner{data: []byte{2}}, &testOwner{data: []byte{3}}
			sender.Enqueue(context.Background(), Datagram{Payload: a.data, Owner: a})
			waitSender(t, started)
			sender.Enqueue(context.Background(), Datagram{Payload: b.data, Owner: b})
			blocked := make(chan error, 1)
			go func() { blocked <- sender.Enqueue(context.Background(), Datagram{Payload: c.data, Owner: c}) }()
			if mode == "cancel" {
				sender.Close()
			} else {
				close(unblock)
				waitSender(t, socket.closed)
				sender.Close()
			}
			if err := <-blocked; err == nil {
				t.Fatal("accepted after stop")
			}
			if c.released.Load() != 0 {
				t.Fatal("failed acceptance stole ownership")
			}
			c.Release()
			if a.released.Load() != 1 || b.released.Load() != 1 {
				t.Fatal("leaked active or queued buffer")
			}
			if mode == "zero" && !errors.Is(sender.Err(), io.ErrNoProgress) {
				t.Fatal(sender.Err())
			}
			if mode == "prefix-error" && !errors.Is(sender.Err(), io.ErrClosedPipe) {
				t.Fatal(sender.Err())
			}
			if calls != 1 {
				t.Fatal("retried a terminal failure", calls)
			}
		})
	}
}
func TestSenderRechecksEligibilityAfterPartialWrite(t *testing.T) {
	socket := newSenderSocket()
	started, unblock := make(chan struct{}), make(chan struct{})
	var eligible atomic.Bool
	eligible.Store(true)
	var seen []byte
	calls := 0
	writer := senderWriter(func(m []Message) (int, error) {
		calls++
		if calls == 1 {
			close(started)
			<-unblock
		}
		seen = append(seen, m[0].Payload[0])
		if calls == 2 {
			eligible.Store(false)
		}
		return 1, nil
	})
	s, _ := NewSenderWithWriter(context.Background(), socket, writer, 8)
	defer s.Close()
	owners := []*testOwner{}
	for i := byte(1); i <= 4; i++ {
		o := &testOwner{data: []byte{i}}
		owners = append(owners, o)
		d := Datagram{Payload: o.data, Owner: o}
		if i == 3 {
			d.Eligible = eligible.Load
		}
		if err := s.Enqueue(context.Background(), d); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			waitSender(t, started)
		}
	}
	close(unblock)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || seen[0] != 1 || seen[1] != 2 || seen[2] != 4 {
		t.Fatal("revoked unsent packet transmitted or reordered", seen)
	}
	for _, o := range owners {
		if o.released.Load() != 1 {
			t.Fatal("owner leak")
		}
	}
}
func TestSenderBackpressureCallerCancellation(t *testing.T) {
	socket := newSenderSocket()
	started := make(chan struct{})
	s, _ := NewSenderWithWriter(context.Background(), socket, senderWriter(func([]Message) (int, error) { close(started); <-socket.closed; return 0, net.ErrClosed }), 1)
	defer s.Close()
	s.Enqueue(context.Background(), Datagram{})
	waitSender(t, started)
	s.Enqueue(context.Background(), Datagram{})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- s.Enqueue(ctx, Datagram{}) }()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("backpressure ignored cancellation")
	}
}

func TestSenderCancellationWhileWaitingForSubmitGate(t *testing.T) {
	socket := newSenderSocket()
	started := make(chan struct{})
	s, _ := NewSenderWithWriter(context.Background(), socket, senderWriter(func([]Message) (int, error) { close(started); <-socket.closed; return 0, net.ErrClosed }), 1)
	defer s.Close()
	s.Enqueue(context.Background(), Datagram{})
	waitSender(t, started)
	s.Enqueue(context.Background(), Datagram{})
	blocked := make(chan error, 1)
	gateHeld := make(chan struct{})
	go func() {
		blocked <- s.Enqueue(context.Background(), Datagram{Eligible: func() bool { close(gateHeld); return true }})
	}()
	waitSender(t, gateHeld)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := make(chan error, 1)
	go func() { result <- s.Enqueue(ctx, Datagram{}) }()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cannot interrupt submit gate")
	}
	s.Close()
	<-blocked
}
