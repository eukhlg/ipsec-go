package server

import (
	"context"
	"errors"
	"net"
	"time"

	"l2tp-go/protocol/isakmp"
)

type IKEEstablishedHandler func(context.Context, net.Addr, isakmp.ESPPair)

type IKEServer struct {
	Conn         net.PacketConn
	ControlPlane *isakmp.ControlPlane
	Established  IKEEstablishedHandler
}

// InstallESPRegistry wires completed Quick Mode pairs into an ESP registry.
func (s *IKEServer) InstallESPRegistry(registry *ESPRegistry) {
	s.Established = func(_ context.Context, peer net.Addr, pair isakmp.ESPPair) { _ = registry.Install(peer, pair) }
}

func ListenIKE(address string, config isakmp.ControlPlaneConfig) (*IKEServer, error) {
	control, err := isakmp.NewControlPlane(config)
	if err != nil {
		return nil, err
	}
	return ListenIKEWithControl(address, control)
}

// ListenIKEWithControl binds an IKE socket to an existing control plane. It is
// used by UDP/500 and the shared UDP/4500 NAT-T demultiplexer.
func ListenIKEWithControl(address string, control *isakmp.ControlPlane) (*IKEServer, error) {
	if control == nil {
		return nil, errors.New("ike server: missing control plane")
	}
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	return &IKEServer{Conn: conn, ControlPlane: control}, nil
}

func (s *IKEServer) Serve(ctx context.Context) error {
	if s.Conn == nil || s.ControlPlane == nil {
		return errors.New("ike server: missing connection or control plane")
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
		result, err := s.ControlPlane.HandleDatagram(peer, buffer[:n], time.Now())
		if err != nil {
			continue
		} // Untrusted malformed datagrams never stop UDP/500.
		if len(result.Reply) != 0 {
			if _, err := s.Conn.WriteTo(result.Reply, peer); err != nil {
				return err
			}
		}
		if result.Established != nil && s.Established != nil {
			s.Established(ctx, peer, *result.Established)
		}
	}
}

func (s *IKEServer) Close() error {
	if s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}
