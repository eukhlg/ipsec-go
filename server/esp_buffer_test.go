package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type receiveBufferConn struct {
	packets [][]byte
	index   int
}

func (c *receiveBufferConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.index == len(c.packets) {
		return 0, nil, io.EOF
	}
	n := copy(p, c.packets[c.index])
	c.index++
	return n, &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil
}
func (c *receiveBufferConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *receiveBufferConn) Close() error                              { return nil }
func (c *receiveBufferConn) LocalAddr() net.Addr                       { return &net.IPAddr{} }
func (c *receiveBufferConn) SetDeadline(time.Time) error               { return nil }
func (c *receiveBufferConn) SetReadDeadline(time.Time) error           { return nil }
func (c *receiveBufferConn) SetWriteDeadline(time.Time) error          { return nil }

func TestReceiveBufferLifetimeThroughDispatch(t *testing.T) {
	conn := &receiveBufferConn{packets: [][]byte{bytes.Repeat([]byte{1}, 100), bytes.Repeat([]byte{2}, 20)}}
	var previous []byte
	dispatched := 0
	s := &ESPTransportServer{Conn: conn}
	s.HandlePacketInPlace = func(_ context.Context, _ net.Addr, wire []byte, _ time.Time) (ESPPacketResult, error) {
		if dispatched == 1 && !bytes.Equal(previous[20:], make([]byte, 80)) {
			t.Fatal("previous plaintext retained before next receive")
		}
		value := byte(dispatched + 1)
		return ESPPacketResult{Dispatch: func(context.Context) error {
			if !bytes.Equal(wire, bytes.Repeat([]byte{value}, len(wire))) {
				t.Fatal("receive buffer reused before final consumer")
			}
			previous = wire
			dispatched++
			return nil
		}}, nil
	}
	if err := s.Serve(context.Background()); err != io.EOF {
		t.Fatal(err)
	}
	if dispatched != 2 {
		t.Fatalf("dispatches=%d", dispatched)
	}
	if !bytes.Equal(previous, make([]byte, len(previous))) {
		t.Fatal("receive buffer not cleared on exit")
	}
}

func TestReceiveDispatchFailureErasesStorage(t *testing.T) {
	conn := &receiveBufferConn{packets: [][]byte{bytes.Repeat([]byte{0xa5}, 100)}}
	var view []byte
	s := &ESPTransportServer{Conn: conn, HandlePacketInPlace: func(_ context.Context, _ net.Addr, wire []byte, _ time.Time) (ESPPacketResult, error) {
		view = wire
		return ESPPacketResult{Dispatch: func(context.Context) error { return io.ErrClosedPipe }}, nil
	}}
	if err := s.Serve(context.Background()); err != io.ErrClosedPipe {
		t.Fatal(err)
	}
	if !bytes.Equal(view, make([]byte, len(view))) {
		t.Fatal("dispatch failure retained plaintext")
	}
}
