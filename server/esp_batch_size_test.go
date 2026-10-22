package server

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNATTBatchSizeValidation(t *testing.T) {
	for _, size := range []int{-1, 257} {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewNATTServer(conn, func(context.Context, net.Addr, []byte, time.Time) (ESPPacketResult, error) {
			return ESPPacketResult{}, nil
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		s.UDPBatchSize = size
		if err := s.Serve(context.Background()); err == nil {
			t.Fatalf("accepted batch %d", size)
		}
		s.Close()
	}
}
