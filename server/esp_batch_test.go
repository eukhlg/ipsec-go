package server

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestNATTBatchDemuxAndDispatchOwnership(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tx, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	// Queue a keepalive, non-ESP marker (no IKE consumer), malformed packet,
	// then two ESP messages. No marker may be stripped from the ESP payload.
	packets := [][]byte{{255}, {0, 0, 0, 0, 1, 2, 3, 4}, {1}, {1, 2, 3, 4, 5, 6, 7, 8}, {2, 3, 4, 5, 6, 7, 8, 9}}
	for _, p := range packets {
		if _, err := tx.WriteTo(p, conn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	count := 0
	received := 0
	s, _ := NewNATTServer(conn, func(_ context.Context, peer net.Addr, wire []byte, _ time.Time) (ESPPacketResult, error) {
		expected := packets[3+received]
		received++
		if peer.String() != tx.LocalAddr().String() || !bytes.Equal(wire, expected) {
			t.Fatalf("wrong demultiplexed packet %v", wire)
		}
		return ESPPacketResult{Dispatch: func(context.Context) error {
			if !bytes.Equal(wire, expected) {
				t.Fatal("buffer reused during Dispatch")
			}
			count++
			if count == 2 {
				cancel()
			}
			return nil
		}}, nil
	}, nil)
	if err := s.Serve(ctx); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatal(count)
	}
}
