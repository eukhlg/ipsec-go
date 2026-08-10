package server

import (
	"context"
	"errors"
	"net"
	"time"

	"l2tp-go/protocol/esp"
)

type ESPResultHandler func(context.Context, ESPBridgeResult) error

type ESPTransportServer struct {
	Conn         net.PacketConn
	Bridge       *ESPBridge
	NATT         bool
	HandleResult ESPResultHandler
}

func ListenRawESP(address string, bridge *ESPBridge) (*ESPTransportServer, error) {
	conn, err := net.ListenPacket("ip4:50", address)
	if err != nil {
		return nil, err
	}
	return &ESPTransportServer{Conn: conn, Bridge: bridge}, nil
}
func ListenNATT(address string, bridge *ESPBridge) (*ESPTransportServer, error) {
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	return &ESPTransportServer{Conn: conn, Bridge: bridge, NATT: true}, nil
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
				continue
			}
			return err
		}
		wire := buffer[:n]
		if s.NATT {
			kind, payload := esp.ClassifyNATT(wire)
			if kind != esp.NATTESP {
				continue
			}
			wire = payload
		}
		result, err := s.Bridge.Handle(peer, wire, time.Now())
		if err != nil {
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
func (s *ESPTransportServer) Close() error {
	if s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}
