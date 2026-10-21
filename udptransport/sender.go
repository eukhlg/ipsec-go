package udptransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const SenderQueueCapacity = 64

var ErrIneligible = errors.New("udp sender: datagram no longer eligible")

type Releaser interface{ Release() }

// Datagram borrows Payload from Owner. Successful Enqueue transfers ownership;
// on failure the caller still owns it. Eligible is rechecked before each write.
type Datagram struct {
	Payload  []byte
	Peer     net.Addr
	Owner    Releaser
	Eligible func() bool
}

func (d Datagram) release() {
	if d.Owner != nil {
		d.Owner.Release()
	}
}

type Writer interface{ Write([]Message) (int, error) }
type queuedDatagram struct {
	datagram Datagram
	barrier  chan struct{}
}

// Sender is one bounded FIFO. It drains immediately available packets only,
// without timers. Close cancels writes, discards queued ownership and joins.
// The connection belongs to Sender and is closed on cancellation or failure.
type Sender struct {
	conn                    net.PacketConn
	writer                  Writer
	ctx                     context.Context
	cancel                  context.CancelFunc
	queue                   chan queuedDatagram
	submit                  chan struct{}
	stopped, watcherStopped chan struct{}
	mu                      sync.Mutex
	err                     error
}

func NewSender(ctx context.Context, conn net.PacketConn, capacity int) (*Sender, error) {
	return NewSenderWithWriter(ctx, conn, New(conn), capacity)
}

// NewSenderWithWriter supports injected batch writers using the same ownership
// and partial-write contract as Conn. It still owns and closes conn.
func NewSenderWithWriter(ctx context.Context, conn net.PacketConn, writer Writer, capacity int) (*Sender, error) {
	if conn == nil || writer == nil || capacity < 1 {
		return nil, errors.New("udp sender: connection, writer and positive capacity required")
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Sender{conn: conn, writer: writer, ctx: ctx, cancel: cancel, queue: make(chan queuedDatagram, capacity), submit: make(chan struct{}, 1), stopped: make(chan struct{}), watcherStopped: make(chan struct{})}
	s.submit <- struct{}{}
	go func() { defer close(s.watcherStopped); <-ctx.Done(); _ = conn.Close() }()
	go s.run()
	return s, nil
}
func (s *Sender) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return s.ctx.Err()
}
func (s *Sender) enqueue(ctx context.Context, q queuedDatagram) error {
	if err := s.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.Err()
	case <-s.submit:
	}
	defer func() { s.submit <- struct{}{} }()
	if err := s.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if q.datagram.Eligible != nil && !q.datagram.Eligible() {
		return ErrIneligible
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.Err()
	case s.queue <- q:
		return nil
	}
}
func (s *Sender) Enqueue(ctx context.Context, d Datagram) error {
	return s.enqueue(ctx, queuedDatagram{datagram: d})
}

// Flush orders a barrier after prior enqueues. Successful return means their
// writes/rejections completed, not merely that they were accepted by the queue.
func (s *Sender) Flush(ctx context.Context) error {
	barrier := make(chan struct{})
	if err := s.enqueue(ctx, queuedDatagram{barrier: barrier}); err != nil {
		return err
	}
	select {
	case <-barrier:
		return s.Err()
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stopped:
		return s.Err()
	}
}
func (s *Sender) Close() { s.cancel(); <-s.stopped }
func (s *Sender) run() {
	var failure error
	defer func() {
		if failure != nil {
			s.mu.Lock()
			s.err = failure
			s.mu.Unlock()
		}
		s.cancel()
		<-s.watcherStopped
		<-s.submit
		for len(s.queue) > 0 {
			q := <-s.queue
			q.datagram.release()
		}
		s.submit <- struct{}{}
		close(s.stopped)
	}()
	var batch [BatchSize]queuedDatagram
	var messages [BatchSize]Message
	var indices [BatchSize]int
	for {
		n := 0
		select {
		case <-s.ctx.Done():
			return
		case batch[0] = <-s.queue:
			n = 1
		}
	drain:
		for n < len(batch) {
			select {
			case batch[n] = <-s.queue:
				n++
			default:
				break drain
			}
		}
		err := func() error {
			defer func() {
				for i := 0; i < n; i++ {
					batch[i].datagram.release()
					batch[i] = queuedDatagram{}
					messages[i] = Message{}
				}
			}()
			for start := 0; start < n; {
				if s.ctx.Err() != nil {
					return s.ctx.Err()
				}
				if batch[start].barrier != nil {
					for i := 0; i < start; i++ {
						batch[i].datagram.release()
						batch[i].datagram.Owner = nil
					}
					close(batch[start].barrier)
					start++
					continue
				}
				end := start
				for end < n && batch[end].barrier == nil {
					end++
				}
				for start < end {
					if s.ctx.Err() != nil {
						return s.ctx.Err()
					}
					count := 0
					for i := start; i < end; i++ {
						d := batch[i].datagram
						if d.Eligible != nil && !d.Eligible() {
							continue
						}
						messages[count] = Message{Payload: d.Payload, Peer: d.Peer}
						indices[count] = i
						count++
					}
					if count == 0 {
						break
					}
					sent, err := s.writer.Write(messages[:count])
					if sent < 0 || sent > count {
						return io.ErrShortWrite
					}
					if err != nil {
						return err
					} // terminally reject the remainder; never retry successes
					if sent == 0 {
						return io.ErrNoProgress
					}
					start = indices[sent-1] + 1
				}
				start = end
			}
			return nil
		}()
		if err != nil {
			if s.ctx.Err() == nil {
				failure = fmt.Errorf("udp sender write: %w", err)
			}
			return
		}
	}
}
