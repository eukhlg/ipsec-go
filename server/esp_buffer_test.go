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

func TestReceiveDispatchFailureErasesStorage(t *testing.T) {
	conn := newPipelineConn(1)
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
