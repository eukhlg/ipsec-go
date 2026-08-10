package server

import (
	"context"
	"errors"
	"net"
	"time"

	"l2tp-go/protocol/esp"
	"l2tp-go/protocol/isakmp"
)

type ESPResultHandler func(context.Context, ESPBridgeResult) error

type ESPTransportServer struct {
	Conn         net.PacketConn
	Bridge       *ESPBridge
	ControlPlane *isakmp.ControlPlane
	NATT         bool
	HandleResult ESPResultHandler
	Established  IKEEstablishedHandler
	Lifecycle    IKELifecycleHandler
	Debugf       func(string, ...any)
}

func ListenRawESP(address string, bridge *ESPBridge) (*ESPTransportServer, error) {
	conn, err := net.ListenPacket("ip4:50", address)
	if err != nil {
		return nil, err
	}
	return &ESPTransportServer{Conn: conn, Bridge: bridge}, nil
}
func ListenNATT(address string, bridge *ESPBridge) (*ESPTransportServer, error) {
	return ListenNATTWithIKE(address, bridge, nil)
}

// ListenNATTWithIKE binds the shared RFC 3948 UDP/4500 socket. IKE packets
// carry the Non-ESP Marker; all other sufficiently large datagrams are ESP.
func ListenNATTWithIKE(address string, bridge *ESPBridge, control *isakmp.ControlPlane) (*ESPTransportServer, error) {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	return &ESPTransportServer{Conn: conn, Bridge: bridge, ControlPlane: control, NATT: true}, nil
}

func (s *ESPTransportServer) Serve(ctx context.Context) error {
	if s.Conn == nil || s.Bridge == nil {
		return errors.New("esp transport server: missing connection or bridge")
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
			s.debug("natt udp/4500 rx peer=%s bytes=%d kind=%d", peer, n, kind)
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
		result, err := s.Bridge.Handle(peer, wire, time.Now())
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
		if s.HandleResult != nil {
			if err := s.HandleResult(ctx, result); err != nil {
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
func (s *ESPTransportServer) Close() error {
	if s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}
