package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/eukhlg/netio/flowhash"
)

// Keyed dispatches keep per-flow order on their worker; every hundredth packet
// is unkeyed and must run after all earlier packets and before any later one.
// Each worker flushes its own delivery batch, and every buffer is released
// exactly once.
func TestDeliveryWorkersFlowOrderBarriersAndOwnership(t *testing.T) {
	for _, workers := range []int{0, 1, 2, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			const n, flows = 2000, 8
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var mu sync.Mutex
			delivered, lastBarrier := 0, 0
			last := map[uint32]uint32{}
			batches := map[*int]bool{}
			s := &ESPTransportServer{Conn: newPipelineConn(n), DeliveryWorkers: workers}
			type batchKey struct{}
			s.NewDeliveryBatch = func(ctx context.Context) (context.Context, func() error) {
				id := new(int)
				mu.Lock()
				batches[id] = true
				mu.Unlock()
				return context.WithValue(ctx, batchKey{}, id), func() error { return nil }
			}
			s.HandlePacketInPlace = func(_ context.Context, _ net.Addr, wire []byte, _ time.Time) (ESPPacketResult, error) {
				value := binary.BigEndian.Uint32(wire)
				flow := value % flows
				barrier := value%100 == 0
				// Spread the flow keys like real hashes, which Shard scales.
				return ESPPacketResult{Flow: flow * 0x9e3779b9, FlowValid: !barrier, Dispatch: func(ctx context.Context) error {
					if id, _ := ctx.Value(batchKey{}).(*int); id == nil {
						t.Error("dispatch outside a worker's delivery batch")
					}
					if b := DeliveryBuffer(ctx); b == nil || binary.BigEndian.Uint32(b.Bytes()) != value {
						t.Error("delivery buffer does not hold the packet")
					}
					mu.Lock()
					defer mu.Unlock()
					delivered++
					switch {
					case barrier && delivered != int(value):
						t.Errorf("barrier %d ran after %d deliveries", value, delivered-1)
					case !barrier && int(value) < lastBarrier:
						t.Errorf("packet %d ran after barrier %d", value, lastBarrier)
					case !barrier && last[flow] >= value:
						t.Errorf("flow %d: %d after %d", flow, value, last[flow])
					}
					if barrier {
						lastBarrier = int(value)
					} else {
						last[flow] = value
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
			if delivered != n {
				t.Fatalf("delivered %d of %d", delivered, n)
			}
			if want := max(workers, 1); len(batches) != want {
				t.Fatalf("%d delivery batches, want %d", len(batches), want)
			}
		})
	}
}

// Two flows on different workers dispatch concurrently: the first waits for
// the second, which a single delivery goroutine would never run.
func TestDeliveryWorkersRunFlowsInParallel(t *testing.T) {
	var a, b uint32 = 0, 1 << 31 // Shard scales the hash: halves map to workers
	if flowhash.Shard(a, 2) == flowhash.Shard(b, 2) {
		t.Fatal("flows share a worker")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	second := make(chan struct{})
	s := &ESPTransportServer{Conn: newPipelineConn(2), DeliveryWorkers: 2}
	s.HandlePacketInPlace = func(_ context.Context, _ net.Addr, wire []byte, _ time.Time) (ESPPacketResult, error) {
		if binary.BigEndian.Uint32(wire) == 1 {
			return ESPPacketResult{Flow: a, FlowValid: true, Dispatch: func(context.Context) error {
				select {
				case <-second:
					cancel()
				case <-time.After(5 * time.Second):
					t.Error("flows did not run in parallel")
					cancel()
				}
				return nil
			}}, nil
		}
		return ESPPacketResult{Flow: b, FlowValid: true, Dispatch: func(context.Context) error { close(second); return nil }}, nil
	}
	pool := newCountedPipelinePool(t)
	if err := s.serve(ctx, pool.acquire, pool.release); err != nil {
		t.Fatal(err)
	}
	pool.check()
}

// A barrier cancelled after reaching only some workers is owned by the copies
// sent; its buffer is released once, by whichever reference goes last.
func TestDeliveryBarrierCancelledMidEnqueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := newCountedPipelinePool(t)
	s := &ESPTransportServer{DeliveryWorkers: 2}
	d := s.newDeliverer(ctx, cancel, pool.release)
	var key uint32 = 1 << 31
	if flowhash.Shard(key, 2) != 1 {
		t.Fatal("key not on the second worker")
	}
	// Block the second worker, then fill its FIFO.
	block, entered := make(chan struct{}), make(chan struct{})
	enqueue := func(dispatch func(context.Context) error) {
		buffer, err := pool.acquire(64)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.enqueue(espDelivery{dispatch: dispatch, buffer: buffer, flow: key, keyed: true}); err != nil {
			t.Fatal(err)
		}
	}
	enqueue(func(context.Context) error { close(entered); <-block; return nil })
	<-entered
	for i := 0; i < cap(d.queues[1]); i++ {
		enqueue(func(context.Context) error { return nil })
	}
	buffer, _ := pool.acquire(64)
	ran := false
	done := make(chan error)
	go func() {
		done <- d.enqueue(espDelivery{dispatch: func(context.Context) error { ran = true; return nil }, buffer: buffer})
	}()
	time.Sleep(20 * time.Millisecond) // the first copy is queued; the second blocks
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("partially enqueued barrier returned %v; the caller would release it twice", err)
	}
	close(block)
	d.close()
	pool.check()
	if ran {
		t.Fatal("cancelled barrier dispatched")
	}
}
