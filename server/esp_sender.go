package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/eukhlg/netio/udptransport"
)

// Compile-time check: the raw ESP socket is written through netio's Sender.
var _ udptransport.Writer = rawESPWriter{}

// ESPSender is the outbound ESP transport on netio, the counterpart of
// l2tp-go's UDPTransport: NAT-T datagrams go through a ShardedSender on the
// UDP 4500 socket (batched, GSO when available), raw ESP through a Sender on
// the IP protocol 50 socket. Each transport keeps FIFO order, and an SA uses
// exactly one transport, so every SA keeps its sequence order on the wire.
// NAT-T egress has one shard; sharding it is a separate decision (it must stay
// inside the peer's replay window).
//
// Producers must serialize sealing and enqueueing for each SA, so enqueue order
// is sequence order. ESPSender owns both sockets: they are closed when it
// stops, after a write failure, cancellation of its context, or Close.
type ESPSender struct {
	cancel context.CancelFunc
	natt   *udptransport.ShardedSender
	raw    *udptransport.Sender
	udp    *udptransport.Conn
	done   chan error
	closed chan struct{}
}

// NewESPSender sends NAT-T in batches of batchSize with options (GSO) and keeps
// up to capacity datagrams queued per transport.
func NewESPSender(ctx context.Context, raw, natt net.PacketConn, capacity, batchSize int, options udptransport.Options) (*ESPSender, error) {
	if natt == nil {
		return nil, errors.New("esp sender: sockets required")
	}
	udp, err := udptransport.NewWithOptions(natt, batchSize, options)
	if err != nil {
		return nil, err
	}
	s, err := NewESPSenderWithWriter(ctx, raw, natt, udp, capacity, batchSize)
	if err == nil {
		s.udp = udp
	}
	return s, err
}

// NewESPSenderWithWriter writes NAT-T batches through writer (which must write
// to natt, with udptransport.Conn's partial-write contract); for tests and
// injected writers.
func NewESPSenderWithWriter(ctx context.Context, raw, natt net.PacketConn, writer udptransport.Writer, capacity, batchSize int) (*ESPSender, error) {
	if raw == nil || natt == nil || writer == nil || capacity < 1 {
		return nil, errors.New("esp sender: sockets, writer and positive capacity required")
	}
	ctx, cancel := context.WithCancel(ctx)
	nattSender, err := udptransport.NewShardedSender(ctx, []udptransport.Shard{{Conn: natt, Writer: writer}}, capacity, batchSize)
	if err != nil {
		cancel()
		return nil, err
	}
	rawSender, err := udptransport.NewSenderWithWriter(ctx, raw, rawESPWriter{raw}, capacity, batchSize)
	if err != nil {
		cancel()
		nattSender.Close()
		return nil, err
	}
	s := &ESPSender{cancel: cancel, natt: nattSender, raw: rawSender, done: make(chan error, 1), closed: make(chan struct{})}
	go s.watch()
	return s, nil
}

// watch stops both transports when either stops and publishes the first write
// failure (nil after a normal shutdown).
func (s *ESPSender) watch() {
	select {
	case <-s.natt.Done():
	case <-s.raw.Done():
	}
	s.cancel()
	<-s.natt.Done()
	<-s.raw.Done()
	var failure error
	for _, err := range []error{s.natt.Err(), s.raw.Err()} {
		if err != nil && !errors.Is(err, context.Canceled) {
			failure = fmt.Errorf("esp sender: %w", err)
			break
		}
	}
	s.done <- failure
	close(s.closed)
}

// Done publishes the first write error even if no producer enqueues again, or
// nil after a normal shutdown. The channel is buffered.
func (s *ESPSender) Done() <-chan error { return s.done }

// Enqueue transfers datagram ownership only on success; on error the producer
// still owns (and must release) it. Accepted datagrams are released by the
// sender after their write, when skipped because the SA stopped being active,
// or at shutdown.
func (s *ESPSender) Enqueue(association *Association, datagram ESPDatagram) error {
	return s.EnqueueContext(context.Background(), association, datagram)
}

// EnqueueContext is Enqueue that also gives up when ctx ends, for producers
// that stop independently of the sender.
func (s *ESPSender) EnqueueContext(ctx context.Context, association *Association, datagram ESPDatagram) error {
	if association == nil || !association.Active() {
		return ErrUnknownESP
	}
	eligible := association.active
	if eligible == nil {
		eligible = association.Active
	}
	d := udptransport.Datagram{Payload: datagram.Payload, Peer: datagram.Peer, Eligible: eligible}
	if datagram.Buffer != nil {
		d.Owner = datagram.Buffer
	}
	var err error
	if datagram.NATT {
		err = s.natt.Enqueue(ctx, d)
	} else {
		err = s.raw.Enqueue(ctx, d)
	}
	if errors.Is(err, udptransport.ErrIneligible) {
		return ErrUnknownESP
	}
	return err
}

// Close discards the backlog, interrupts an active write and joins both
// transports.
func (s *ESPSender) Close() {
	s.cancel()
	<-s.closed
}

// GSOEnabled reports whether NAT-T batches use UDP GSO.
func (s *ESPSender) GSOEnabled() bool { return s.udp != nil && s.udp.GSOEnabled() }

// rawESPWriter writes ESP to the raw IP socket one datagram at a time; peers
// given as UDP addresses are sent to their IP.
type rawESPWriter struct{ conn net.PacketConn }

func (w rawESPWriter) Write(messages []udptransport.Message) (int, error) {
	for i, m := range messages {
		peer := m.Peer
		if addr, ok := peer.(*net.UDPAddr); ok {
			peer = &net.IPAddr{IP: addr.IP, Zone: addr.Zone}
		}
		n, err := w.conn.WriteTo(m.Payload, peer)
		if err != nil {
			return i, err
		}
		if n != len(m.Payload) {
			return i, io.ErrShortWrite
		}
	}
	return len(messages), nil
}
