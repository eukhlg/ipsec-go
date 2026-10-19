package server

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/eukhlg/ipsec-go/protocol/isakmp"
)

type IKEEstablishedHandler func(context.Context, net.Addr, isakmp.ESPPair)
type IKELifecycleHandler func(context.Context, []isakmp.LifecycleEvent)

type IKEServer struct {
	Conn         net.PacketConn
	ControlPlane *isakmp.ControlPlane
	Established  IKEEstablishedHandler
	Lifecycle    IKELifecycleHandler
	Debugf       func(string, ...any)
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
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	server, err := NewIKEServer(conn, control)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return server, nil
}

// NewIKEServer creates an IKE server over a caller-owned packet connection.
func NewIKEServer(conn net.PacketConn, control *isakmp.ControlPlane) (*IKEServer, error) {
	if conn == nil || control == nil {
		return nil, errors.New("ike server: packet connection and control plane are required")
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
				s.handleMaintenance(ctx)
				continue
			}
			return err
		}
		result, err := s.ControlPlane.HandleDatagram(peer, buffer[:n], time.Now())
		if err != nil {
			s.debug("ike udp/500 drop peer=%s bytes=%d error=%v", peer, n, err)
			s.handleMaintenance(ctx)
			continue
		} // Untrusted malformed datagrams never stop UDP/500.
		if len(result.Reply) != 0 {
			if _, err := s.Conn.WriteTo(result.Reply, peer); err != nil {
				return err
			}
			s.debug("ike udp/500 tx peer=%s bytes=%d", peer, len(result.Reply))
		}
		if result.Established != nil && s.Established != nil {
			s.Established(ctx, peer, *result.Established)
		}
		if len(result.Lifecycle) != 0 && s.Lifecycle != nil {
			s.Lifecycle(ctx, result.Lifecycle)
		}
		s.handleMaintenance(ctx)
	}
}

func (s *IKEServer) debug(format string, args ...any) {
	if s.Debugf != nil {
		s.Debugf(format, args...)
	}
}

func (s *IKEServer) handleMaintenance(ctx context.Context) {
	if s.Lifecycle != nil {
		if events := s.ControlPlane.Maintain(time.Now()); len(events) != 0 {
			s.Lifecycle(ctx, events)
		}
	}
}

func (s *IKEServer) Close() error {
	if s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}
