package server

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eukhlg/netio/flowhash"
	"github.com/eukhlg/netio/packetbuf"
)

type espDelivery struct {
	dispatch func(context.Context) error
	buffer   *packetbuf.Buffer
	flow     uint32
	keyed    bool
	// barrier is set on every worker's copy of an unkeyed delivery when
	// several workers run.
	barrier *deliveryBarrier
}

// deliveryBarrier orders an unkeyed delivery against all others. Every worker
// receives a copy; each writes what it holds and waits, and the last to arrive
// dispatches it. refs counts the copies still holding the buffer.
type deliveryBarrier struct {
	workers int32
	arrived atomic.Int32
	refs    atomic.Int32
	done    chan struct{}
}

// espDeliverer runs post-commit dispatch on one or more workers. A keyed
// delivery goes to the worker its flow maps to, so one flow keeps its order;
// an unkeyed one is a barrier across all workers. One worker keeps the single
// FIFO of earlier versions and never builds barriers.
type espDeliverer struct {
	server  *ESPTransportServer
	ctx     context.Context
	cancel  context.CancelFunc
	release func(*packetbuf.Buffer)
	queues  []chan espDelivery
	started []atomic.Int64 // per worker: start of the running batch, or zero
	wg      sync.WaitGroup
	mu      sync.Mutex
	err     error
}

func (s *ESPTransportServer) newDeliverer(ctx context.Context, cancel context.CancelFunc, release func(*packetbuf.Buffer)) *espDeliverer {
	n := min(max(s.DeliveryWorkers, 1), ESPDeliveryCapacity)
	d := &espDeliverer{server: s, ctx: ctx, cancel: cancel, release: release, queues: make([]chan espDelivery, n), started: make([]atomic.Int64, n)}
	capacity := (ESPDeliveryCapacity + n - 1) / n
	for i := range d.queues {
		d.queues[i] = make(chan espDelivery, capacity)
	}
	d.wg.Add(n)
	for i := range d.queues {
		go d.run(i)
	}
	return d
}

func (d *espDeliverer) send(queue chan espDelivery, item espDelivery) error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	select {
	case queue <- item:
		return nil
	case <-d.ctx.Done():
		return d.ctx.Err()
	}
}

// enqueue transfers item.buffer on success; on failure the caller keeps it.
func (d *espDeliverer) enqueue(item espDelivery) error {
	n := len(d.queues)
	if n == 1 {
		return d.send(d.queues[0], item)
	}
	if item.keyed {
		return d.send(d.queues[flowhash.Shard(item.flow, n)], item)
	}
	b := &deliveryBarrier{workers: int32(n), done: make(chan struct{})}
	b.refs.Store(int32(n))
	item.barrier = b
	for k, queue := range d.queues {
		if err := d.send(queue, item); err != nil {
			if k == 0 {
				return err
			}
			// Delivery is cancelled. The enqueued copies own the buffer;
			// drop the references of those never sent.
			if b.refs.Add(-int32(n-k)) == 0 {
				d.release(item.buffer)
			}
			return nil
		}
	}
	return nil
}

// close stops accepting work and waits until every worker has drained its
// FIFO; cancelled deliveries are skipped and their buffers released.
func (d *espDeliverer) close() {
	for _, queue := range d.queues {
		close(queue)
	}
	d.wg.Wait()
}

func (d *espDeliverer) fail(err error) {
	d.mu.Lock()
	if d.err == nil {
		d.err = err
	}
	d.mu.Unlock()
	d.cancel()
}

func (d *espDeliverer) failure() error { d.mu.Lock(); defer d.mu.Unlock(); return d.err }

func (d *espDeliverer) run(worker int) {
	defer d.wg.Done()
	s, queue := d.server, d.queues[worker]
	// One context value per delivery goroutine; its slot is updated per
	// packet, so dispatch allocates nothing per packet.
	current := &deliveryBufferSlot{}
	ctx := context.WithValue(d.ctx, deliveryBufferKey{}, current)
	flush := func() error { return nil }
	if s.NewDeliveryBatch != nil {
		ctx, flush = s.NewDeliveryBatch(ctx)
	}
	flushed := func() {
		if err := flush(); err != nil {
			d.fail(err)
		}
	}
	batch := make([]espDelivery, 0, cap(queue))
	for first := range queue {
		batch = append(batch[:0], first)
	drain:
		for s.NewDeliveryBatch != nil && len(batch) < cap(queue) {
			select {
			case item, ok := <-queue:
				if !ok {
					break drain
				}
				batch = append(batch, item)
			default:
				break drain
			}
		}
		d.started[worker].Store(time.Now().UnixNano())
		for i := range batch {
			item := &batch[i]
			b := item.barrier
			if b == nil {
				d.dispatch(ctx, current, item)
				continue
			}
			// Everything this worker accepted before the barrier is written
			// before it runs, and nothing after it runs before it finishes.
			flushed()
			if b.arrived.Add(1) == b.workers {
				d.dispatch(ctx, current, item)
				flushed()
				close(b.done)
				continue
			}
			select {
			case <-b.done:
			case <-d.ctx.Done():
			}
		}
		flushed()
		d.started[worker].Store(0)
		for i := range batch {
			if b := batch[i].barrier; b == nil || b.refs.Add(-1) == 0 {
				d.release(batch[i].buffer)
			}
			batch[i] = espDelivery{}
		}
	}
}

func (d *espDeliverer) dispatch(ctx context.Context, current *deliveryBufferSlot, item *espDelivery) {
	if d.ctx.Err() != nil {
		return
	}
	current.buffer = item.buffer
	err := item.dispatch(ctx)
	current.buffer = nil
	if err != nil {
		d.fail(err)
	}
}

// stalled reports the longest-running batch, or zero.
func (d *espDeliverer) stalled(now time.Time) time.Duration {
	var longest time.Duration
	for i := range d.started {
		if start := d.started[i].Load(); start != 0 {
			longest = max(longest, now.Sub(time.Unix(0, start)))
		}
	}
	return longest
}

// full reports whether any worker FIFO is full, and its capacity.
func (d *espDeliverer) full() (bool, int) {
	for _, queue := range d.queues {
		if len(queue) == cap(queue) {
			return true, cap(queue)
		}
	}
	return false, 0
}
