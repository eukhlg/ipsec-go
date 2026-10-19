package server

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
)

// ESPPacketResult separates protocol replies from application event dispatch.
// Dispatch runs only after replies have been written successfully.
type ESPPacketResult struct {
	Datagrams []ESPDatagram
	Dispatch  func(context.Context) error
}
type ESPPacketHandler func(context.Context, net.Addr, []byte, time.Time) (ESPPacketResult, error)

type ESPTransportServer struct {
	Conn         net.PacketConn
	HandlePacket ESPPacketHandler
	ControlPlane *isakmp.ControlPlane
	NATT         bool
	Established  IKEEstablishedHandler
	Lifecycle    IKELifecycleHandler
	Debugf       func(string, ...any)
	Tracef       func(string, ...any)
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

func (s *ESPTransportServer) Serve(ctx context.Context) error {
	if s.Conn == nil || s.HandlePacket == nil {
		return errors.New("esp transport server: missing connection or handler")
	}
	buffer := make([]byte, 65535)
	for {
		if err := s.Conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}
		n, peer, err := s.Conn.ReadFrom(buffer)
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
		wire := buffer[:n]
		if s.NATT {
			kind, payload := esp.ClassifyNATT(wire)
			s.trace("natt udp/4500 rx peer=%s bytes=%d kind=%d", peer, n, kind)
			switch kind {
			case esp.NATTKeepalive:
				continue
			case esp.NATTIKE:
				if s.ControlPlane == nil {
					continue
				}
				result, err := s.ControlPlane.HandleNATTDatagram(peer, payload, time.Now())
				if err != nil {
					s.debug("natt ike drop peer=%s bytes=%d error=%v", peer, len(payload), err)
					if s.Lifecycle != nil {
						if events := s.ControlPlane.Maintain(time.Now()); len(events) != 0 {
							s.Lifecycle(ctx, events)
						}
					}
					continue
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
				continue
			case esp.NATTESP:
				wire = payload
			default:
				continue
			}
		}
		result, err := s.HandlePacket(ctx, peer, wire, time.Now())
		if err != nil {
			s.debug("esp drop peer=%s natt=%t bytes=%d error=%v", peer, s.NATT, len(wire), err)
			continue
		}
		for _, reply := range result.Datagrams {
			if reply.NATT != s.NATT {
				continue
			}
			payload := reply.Payload
			if s.NATT {
				payload = esp.EncapsulateNATTESP(payload)
			}
			if _, err := s.Conn.WriteTo(payload, reply.Peer); err != nil {
				return err
			}
		}
		if result.Dispatch != nil {
			if err := result.Dispatch(ctx); err != nil {
				return err
			}
		}
	}
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
func (s *ESPTransportServer) Close() error {
	if s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}
