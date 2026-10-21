package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/eukhlg/ipsec-go/packetbuf"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	"github.com/eukhlg/ipsec-go/udptransport"
)

// ESPPacketResult separates protocol replies from application event dispatch.
// Dispatch runs only after replies have been written successfully.
type ESPPacketResult struct {
	Datagrams []ESPDatagram
	Dispatch  func(context.Context) error
}
type ESPPacketHandler func(context.Context, net.Addr, []byte, time.Time) (ESPPacketResult, error)

// ESPDeliveryCapacity bounds pending borrowed packets per listener. Together
// with the receive batch and one executing callback this bounds packet storage.
const ESPDeliveryCapacity = 64

type espDelivery struct {
	dispatch func(context.Context) error
	buffer   *packetbuf.Buffer
}

type ESPTransportServer struct {
	closeMu sync.Mutex
	closed  chan struct{}

	Conn         net.PacketConn
	HandlePacket ESPPacketHandler
	// HandlePacketInPlace, when set, may mutate the owned receive buffer and
	// borrow its data through Dispatch. It must not retain slices after Dispatch.
	HandlePacketInPlace ESPPacketHandler
	ControlPlane        *isakmp.ControlPlane
	NATT                bool
	Established         IKEEstablishedHandler
	Lifecycle           IKELifecycleHandler
	Debugf              func(string, ...any)
	Tracef              func(string, ...any)
}

func ListenRawESP(address string, handler ESPPacketHandler) (*ESPTransportServer, error) {
	conn, err := net.ListenPacket("ip4:50", address)
	if err != nil {
		return nil, err
	}
	server, err := NewRawESPServer(conn, handler)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return server, nil
}
func ListenNATT(address string, handler ESPPacketHandler) (*ESPTransportServer, error) {
	return ListenNATTWithIKE(address, handler, nil)
}

// ListenNATTWithIKE binds the shared RFC 3948 UDP/4500 socket. IKE packets
// carry the Non-ESP Marker; all other sufficiently large datagrams are ESP.
func ListenNATTWithIKE(address string, handler ESPPacketHandler, control *isakmp.ControlPlane) (*ESPTransportServer, error) {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	server, err := NewNATTServer(conn, handler, control)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return server, nil
}

// NewRawESPServer creates a raw ESP transport over an injected connection.
func NewRawESPServer(conn net.PacketConn, handler ESPPacketHandler) (*ESPTransportServer, error) {
	if conn == nil || handler == nil {
		return nil, errors.New("esp server: packet connection and handler are required")
	}
	return &ESPTransportServer{Conn: conn, HandlePacket: handler}, nil
}

// NewNATTServer creates a UDP/4500 ESP transport over an injected connection.
// control may be nil when IKE demultiplexing is handled by the embedder.
func NewNATTServer(conn net.PacketConn, handler ESPPacketHandler, control *isakmp.ControlPlane) (*ESPTransportServer, error) {
	if conn == nil || handler == nil {
		return nil, errors.New("esp server: packet connection and handler are required")
	}
	return &ESPTransportServer{Conn: conn, HandlePacket: handler, ControlPlane: control, NATT: true}, nil
}

func (s *ESPTransportServer) Serve(parent context.Context) error {
	return s.serve(parent, packetbuf.Acquire, (*packetbuf.Buffer).Release)
}

// The private pool seam permits exact ownership accounting in receive tests.
func (s *ESPTransportServer) serve(parent context.Context, acquire func(int) (*packetbuf.Buffer, error), release func(*packetbuf.Buffer)) (serveErr error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if s.Conn == nil || (s.HandlePacket == nil && s.HandlePacketInPlace == nil) {
		return errors.New("esp transport server: missing connection or handler")
	}
	queue := make(chan espDelivery, ESPDeliveryCapacity)
	deliveryDone := make(chan struct{})
	var deliveryErr error // published by closing deliveryDone
	go func() {
		defer close(deliveryDone)
		for item := range queue {
			if ctx.Err() == nil {
				if err := item.dispatch(ctx); err != nil {
					deliveryErr = err
					cancel()
				}
			}
			release(item.buffer)
		}
	}()
	stopped := make(chan struct{})
	closed := s.closeSignal()
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
		case <-closed:
			cancel()
		}
		// Wake a pending socket read. The connection remains owned by the caller.
		_ = s.Conn.SetReadDeadline(time.Now())
	}()
	defer func() {
		cancel()
		close(queue)
		<-deliveryDone
		<-stopped
		if deliveryErr != nil {
			serveErr = deliveryErr
		} else if parent.Err() != nil {
			serveErr = nil
		}
	}()

	size := 1
	udp := udptransport.New(s.Conn)
	if s.NATT {
		size = udp.BatchSize()
	}
	buffers := make([]*packetbuf.Buffer, 0, size)
	messages := make([]udptransport.Message, size)
	receiveSlots := make([]packetbuf.ReceiveSlot, size)
	defer func() {
		for _, b := range buffers {
			if b != nil {
				release(b)
			}
		}
	}()
	for i := range messages {
		b, err := acquire(packetbuf.MaxPacket)
		if err != nil {
			return err
		}
		buffers = append(buffers, b)
		receiveSlots[i].Buffer = b
	}

	handler := s.HandlePacket
	if s.HandlePacketInPlace != nil {
		handler = s.HandlePacketInPlace
	}
	// The socket owns only this synchronous writable loan. Returned lengths
	// bound erasure; ordinary Bytes exposure would conservatively dirty 64 KiB.
	read := func(slots []packetbuf.ReceiveSlot) (int, error) {
		for i := range slots {
			messages[i].Payload = slots[i].Payload
		}
		var count int
		var err error
		if s.NATT {
			count, err = udp.Read(messages)
		} else {
			messages[0].N, messages[0].Peer, err = s.Conn.ReadFrom(messages[0].Payload)
			if err == nil {
				count = 1
			}
		}
		for i := 0; i < count; i++ {
			slots[i].N = messages[i].N
			if messages[i].Truncated {
				slots[i].N = len(slots[i].Payload)
			}
		}
		return count, err
	}
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := s.Conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		count, err := packetbuf.Receive(receiveSlots, read)
		for i := 0; i < count; i++ {
			messages[i].Payload = receiveSlots[i].Payload
		}

		for i := 0; i < count; i++ {
			if ctx.Err() != nil {
				return nil
			}
			m := &messages[i]
			if !m.Truncated && m.N >= 0 && m.N <= len(m.Payload) {
				if processErr := s.processMessageDispatch(ctx, handler, m.Peer, m.Payload[:m.N:m.N], func(dispatch func(context.Context) error) error {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					select {
					case queue <- espDelivery{dispatch: dispatch, buffer: buffers[i]}:
						buffers[i] = nil // successful enqueue transfers exclusive ownership
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				}); processErr != nil {
					return processErr
				}
			}
			// Each packet has one owner. Release erases all potentially written storage, including
			// plaintext outside the received wire view, before pool reuse.
			if buffers[i] != nil {
				release(buffers[i])
			}
			buffers[i] = nil
			b, acquireErr := acquire(packetbuf.MaxPacket)
			if acquireErr != nil {
				return acquireErr
			}
			buffers[i] = b
			receiveSlots[i].Buffer = b
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if s.ControlPlane != nil && s.Lifecycle != nil {
					if events := s.ControlPlane.Maintain(time.Now()); len(events) != 0 {
						s.Lifecycle(ctx, events)
					}
				}
				continue
			}
			return err
		}
	}
}

func (s *ESPTransportServer) processMessage(ctx context.Context, handler ESPPacketHandler, peer net.Addr, wire []byte) error {
	return s.processMessageDispatch(ctx, handler, peer, wire, func(dispatch func(context.Context) error) error { return dispatch(ctx) })
}

func (s *ESPTransportServer) processMessageDispatch(ctx context.Context, handler ESPPacketHandler, peer net.Addr, wire []byte, deliver func(func(context.Context) error) error) error {
	n := len(wire)
	if s.NATT {
		kind, payload := esp.ClassifyNATT(wire)
		s.trace("natt udp/4500 rx peer=%s bytes=%d kind=%d", peer, n, kind)
		switch kind {
		case esp.NATTKeepalive:
			return nil
		case esp.NATTIKE:
			if s.ControlPlane == nil {
				return nil
			}
			result, err := s.ControlPlane.HandleNATTDatagram(peer, payload, time.Now())
			if err != nil {
				s.debug("natt ike drop peer=%s bytes=%d error=%v", peer, len(payload), err)
				if s.Lifecycle != nil {
					if events := s.ControlPlane.Maintain(time.Now()); len(events) != 0 {
						s.Lifecycle(ctx, events)
					}
				}
				return nil
			}
			if len(result.Reply) != 0 {
				if _, err := s.Conn.WriteTo(esp.EncapsulateNATTIKE(result.Reply), peer); err != nil {
					return err
				}
				s.debug("natt ike tx peer=%s bytes=%d", peer, len(result.Reply)+4)
			}
			if result.Established != nil && s.Established != nil {
				s.Established(ctx, peer, *result.Established)
			}
			if len(result.Lifecycle) != 0 && s.Lifecycle != nil {
				s.Lifecycle(ctx, result.Lifecycle)
			}
			if s.Lifecycle != nil {
				if events := s.ControlPlane.Maintain(time.Now()); len(events) != 0 {
					s.Lifecycle(ctx, events)
				}
			}
			return nil
		case esp.NATTESP:
			wire = payload
		default:
			return nil
		}
	}
	result, err := handler(ctx, peer, wire, time.Now())
	if err != nil {
		s.debug("esp drop peer=%s natt=%t bytes=%d error=%v", peer, s.NATT, len(wire), err)
		return nil
	}
	if err := func() error {
		defer func() {
			for _, reply := range result.Datagrams {
				reply.Release()
			}
		}()
		for _, reply := range result.Datagrams {
			if reply.NATT != s.NATT {
				continue
			}
			// NAT-T ESP has no extra marker; write the same ciphertext directly.
			if _, err := s.Conn.WriteTo(reply.Payload, reply.Peer); err != nil {
				return err
			}
		}
		if result.Dispatch != nil {
			return deliver(result.Dispatch)
		}
		return nil
	}(); err != nil {
		return err
	}
	return nil
}

func (s *ESPTransportServer) debug(format string, args ...any) {
	if s.Debugf != nil {
		s.Debugf(format, args...)
	}
}
func (s *ESPTransportServer) trace(format string, args ...any) {
	if s.Tracef != nil {
		s.Tracef(format, args...)
	}
}
func (s *ESPTransportServer) closeSignal() <-chan struct{} {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed == nil {
		s.closed = make(chan struct{})
	}
	return s.closed
}

func (s *ESPTransportServer) Close() error {
	s.closeMu.Lock()
	if s.closed == nil {
		s.closed = make(chan struct{})
	}
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.closeMu.Unlock()
	if s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}
