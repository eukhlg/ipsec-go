package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/eukhlg/netio/ordered"
	"github.com/eukhlg/netio/packetbuf"
)

// ESPReceiveCapacity bounds all submitted tickets, including running workers
// and completed packets waiting behind a slow earlier ticket. A full window
// blocks the reader without dropping. Delivery retains its separate FIFO bound.
const ESPReceiveCapacity = 64

type espReceiveWork struct {
	packet *ESPReceive
	peer   net.Addr
	now    time.Time
	buffer *packetbuf.Buffer
}

// espReceivePipeline decrypts on workers and commits replay state and
// delivers in arrival order, on netio's ordered pool.
type espReceivePipeline struct {
	ctx     context.Context
	cancel  context.CancelFunc
	server  *ESPTransportServer
	pool    *ordered.Pool[espReceiveWork]
	mu      sync.Mutex
	err     error
	release func(*packetbuf.Buffer)
	enqueue func(espDelivery) error
	crypto  func(*ESPReceive)
	// receives recycles prechecked packets once committed or discarded, so a
	// packet in flight allocates nothing.
	receives sync.Pool
}

func (p *espReceivePipeline) receive() *ESPReceive {
	if r, ok := p.receives.Get().(*ESPReceive); ok {
		return r
	}
	return new(ESPReceive)
}

// recycle returns r once nothing refers to it, without its references to
// the SA and the received storage.
func (p *espReceivePipeline) recycle(r *ESPReceive) {
	*r = ESPReceive{}
	p.receives.Put(r)
}

func (s *ESPTransportServer) newReceivePipeline(ctx context.Context, cancel context.CancelFunc, release func(*packetbuf.Buffer), enqueue func(espDelivery) error) *espReceivePipeline {
	p := &espReceivePipeline{ctx: ctx, cancel: cancel, server: s, release: release, enqueue: enqueue, crypto: (*ESPReceive).Authenticate}
	p.pool = ordered.New(ctx, min(s.ReceiveWorkers, ESPReceiveCapacity), ESPReceiveCapacity, p.authenticate, p.finish, p.discard)
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
func (p *espReceivePipeline) authenticate(w espReceiveWork) (out espReceiveWork) {
	out = w // a recovered panic still returns the item and its buffer
	defer func() {
		if r := recover(); r != nil {
			p.fail(fmt.Errorf("esp receive worker panic: %v", r))
		}
	}()
	if p.ctx.Err() == nil {
		p.crypto(w.packet)
	}
	return w
}

// submit transfers buffer and packet to the pipeline on success; on failure
// the caller keeps them. peer is retained without a copy: received peers are
// never modified once returned (netio's Message.Peer is read-only and shared,
// and ReadFrom returns a new address).
func (p *espReceivePipeline) submit(packet *ESPReceive, peer net.Addr, now time.Time, buffer *packetbuf.Buffer) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if err := p.pool.Submit(espReceiveWork{packet: packet, peer: peer, now: now, buffer: buffer}); err != nil {
		if ctxErr := p.ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	return nil
}

// discard frees an accepted packet that will not be committed.
func (p *espReceivePipeline) discard(w espReceiveWork) {
	if w.buffer != nil {
		p.release(w.buffer)
	}
	p.recycle(w.packet)
}
func (p *espReceivePipeline) finish(ctx context.Context, w espReceiveWork) {
	defer func() {
		if r := recover(); r != nil {
			p.fail(fmt.Errorf("esp committer panic: %v", r))
		}
		if w.buffer != nil {
			p.release(w.buffer)
		}
		p.recycle(w.packet)
	}()
	if ctx.Err() != nil {
		return
	}
	association, payload, next, err := w.packet.Commit()
	if err != nil {
		p.server.debugDrop("esp commit drop", w.peer, err, "esp commit drop peer=%s error=%v", w.peer, err)
		return
	}
	result, err := p.server.HandleDecrypted(ctx, association, w.peer, payload, next, w.now)
	if err != nil {
		p.server.debugDrop("esp plaintext drop", w.peer, err, "esp plaintext drop peer=%s error=%v", w.peer, err)
		return
	}
	if err = p.server.deliverResult(ctx, result, func(item espDelivery) error {
		item.buffer = w.buffer
		if err := p.enqueue(item); err != nil {
			return err
		}
		w.buffer = nil // delivery exclusively owns storage after successful enqueue
		return nil
	}); err != nil && ctx.Err() == nil {
		p.fail(err)
	}
}

// closeAndWait completes every submitted packet, or discards them if the
// pipeline was cancelled, and joins the workers.
func (p *espReceivePipeline) closeAndWait() { p.pool.Drain() }
