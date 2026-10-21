package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/eukhlg/netio/packetbuf"
)

// ESPReceiveCapacity bounds all submitted tickets, including running workers
// and completed packets waiting behind a slow earlier ticket. A full window
// blocks the reader without dropping. Delivery retains its separate FIFO bound.
const ESPReceiveCapacity = 64

type espReceiveWork struct {
	ticket uint64
	packet *ESPReceive
	peer   net.Addr
	now    time.Time
	buffer *packetbuf.Buffer
}

type espReceivePipeline struct {
	ctx       context.Context
	cancel    context.CancelFunc
	server    *ESPTransportServer
	jobs      chan *espReceiveWork
	completed chan *espReceiveWork
	permits   chan struct{}
	done      chan struct{}
	next      uint64 // reader owns
	mu        sync.Mutex
	err       error
	release   func(*packetbuf.Buffer)
	enqueue   func(espDelivery) error
	crypto    func(*ESPReceive)
}

func (s *ESPTransportServer) newReceivePipeline(ctx context.Context, cancel context.CancelFunc, release func(*packetbuf.Buffer), enqueue func(espDelivery) error) *espReceivePipeline {
	p := &espReceivePipeline{ctx: ctx, cancel: cancel, server: s, jobs: make(chan *espReceiveWork, ESPReceiveCapacity), completed: make(chan *espReceiveWork, ESPReceiveCapacity), permits: make(chan struct{}, ESPReceiveCapacity), done: make(chan struct{}), release: release, enqueue: enqueue, crypto: (*ESPReceive).Authenticate}
	var workers sync.WaitGroup
	count := min(s.ReceiveWorkers, ESPReceiveCapacity)
	workers.Add(count)
	for i := 0; i < count; i++ {
		go func() {
			defer workers.Done()
			for w := range p.jobs {
				if ctx.Err() == nil {
					p.authenticate(w)
				}
				p.completed <- w
			}
		}()
	}
	go func() { workers.Wait(); close(p.completed) }()
	go p.commit()
	return p
}
func (p *espReceivePipeline) fail(err error) {
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
	p.cancel()
}
func (p *espReceivePipeline) failure() error { p.mu.Lock(); defer p.mu.Unlock(); return p.err }
func (p *espReceivePipeline) authenticate(w *espReceiveWork) {
	defer func() {
		if r := recover(); r != nil {
			p.fail(fmt.Errorf("esp receive worker panic: %v", r))
		}
	}()
	p.crypto(w.packet)
}
func (p *espReceivePipeline) submit(packet *ESPReceive, peer net.Addr, now time.Time, buffer *packetbuf.Buffer) error {
	select {
	case p.permits <- struct{}{}:
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
	w := &espReceiveWork{ticket: p.next, packet: packet, peer: clonePeer(peer), now: now, buffer: buffer}
	select {
	case p.jobs <- w:
		p.next++
		return nil
	case <-p.ctx.Done():
		<-p.permits
		return p.ctx.Err()
	}
}
func (p *espReceivePipeline) finish(w *espReceiveWork) {
	defer func() {
		if r := recover(); r != nil {
			p.fail(fmt.Errorf("esp committer panic: %v", r))
		}
		if w.buffer != nil {
			p.release(w.buffer)
		}
		<-p.permits
	}()
	if p.ctx.Err() != nil {
		return
	}
	association, payload, next, err := w.packet.Commit()
	if err != nil {
		p.server.debug("esp commit drop peer=%s error=%v", w.peer, err)
		return
	}
	result, err := p.server.HandleDecrypted(p.ctx, association, w.peer, payload, next, w.now)
	if err != nil {
		p.server.debug("esp plaintext drop peer=%s error=%v", w.peer, err)
		return
	}
	if err = p.server.deliverResult(p.ctx, result, func(dispatch func(context.Context) error) error {
		if err := p.enqueue(espDelivery{dispatch: dispatch, buffer: w.buffer}); err != nil {
			return err
		}
		w.buffer = nil // delivery exclusively owns storage after successful enqueue
		return nil
	}); err != nil && p.ctx.Err() == nil {
		p.fail(err)
	}
}
func (p *espReceivePipeline) commit() {
	defer close(p.done)
	next := uint64(0)
	pending := make(map[uint64]*espReceiveWork, ESPReceiveCapacity)
	for w := range p.completed {
		pending[w.ticket] = w
		for {
			head := pending[next]
			if head == nil {
				break
			}
			delete(pending, next)
			p.finish(head)
			next++
		}
	}
	// All submitted jobs reach completed, even after cancellation or worker panic.
	// There are consequently no missing tickets or buffers when done closes.
}
func (p *espReceivePipeline) closeAndWait() { close(p.jobs); <-p.done }
