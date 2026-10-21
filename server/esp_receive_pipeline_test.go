package server

import (
	"context"
	"encoding/binary"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	"github.com/eukhlg/netio/packetbuf"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func receiveFixture(t *testing.T) (*ESPRegistry, *esp.SA, net.Addr) {
	t.Helper()
	r := NewESPRegistry()
	t.Cleanup(r.Close)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
	pair := testESPPair(isakmp.EncapsulationNATTTransport)
	if err := r.Install(peer, pair); err != nil {
		t.Fatal(err)
	}
	client, err := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey})
	if err != nil {
		t.Fatal(err)
	}
	return r, client, peer
}
func TestParallelReceiveOrderAndOwnership(t *testing.T) {
	for _, workers := range []int{0, 1, 2, 4, 8} {
		for _, natt := range []bool{false, true} {
			t.Run(string(rune('0'+workers))+map[bool]string{true: "natt", false: "raw"}[natt], func(t *testing.T) {
				r, client, peer := receiveFixture(t)
				pair := testESPPair(isakmp.EncapsulationNATTTransport)
				pair.Inbound.SPI++
				pair.Outbound.SPI++
				pair.ResponderCookie = isakmp.Cookie{9}
				if err := r.Install(peer, pair); err != nil {
					t.Fatal(err)
				}
				second, _ := esp.NewSA(esp.SAConfig{SPI: pair.Inbound.SPI, Transform: pair.Transform, EncryptionKey: pair.Inbound.EncryptionKey, AuthenticationKey: pair.Inbound.AuthenticationKey})
				const n = 1000
				conn := newPipelineConn(0)
				conn.packets = make(chan []byte, n*3)
				for i := 1; i <= n; i++ {
					payload := make([]byte, 4)
					binary.BigEndian.PutUint32(payload, uint32(i))
					sender := client
					if i%2 == 0 {
						sender = second
					}
					wire, err := sender.Seal(payload, 17)
					if err != nil {
						t.Fatal(err)
					}
					conn.packets <- wire
					// Both in-flight duplicates and forged high sequences must not commit.
					if i%10 == 0 {
						conn.packets <- append([]byte(nil), wire...)
						bad := append([]byte(nil), wire...)
						binary.BigEndian.PutUint32(bad[4:8], uint32(i+100000))
						conn.packets <- bad
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				delivered := 0
				s := &ESPTransportServer{Conn: conn, NATT: natt, Registry: r, ReceiveWorkers: workers, HandlePacket: func(context.Context, net.Addr, []byte, time.Time) (ESPPacketResult, error) {
					panic("legacy handler called")
				}}
				s.HandleDecrypted = func(_ context.Context, _ *Association, _ net.Addr, payload []byte, _ uint8, _ time.Time) (ESPPacketResult, error) {
					value := binary.BigEndian.Uint32(payload)
					return ESPPacketResult{Dispatch: func(context.Context) error {
						delivered++
						if value != uint32(delivered) || binary.BigEndian.Uint32(payload) != value {
							t.Errorf("order/storage %d != %d", value, delivered)
						}
						if delivered == n {
							cancel()
						}
						return nil
					}}, nil
				}
				pool := newCountedPipelinePool(t)
				if err := s.serve(ctx, pool.acquire, pool.release); err != nil {
					t.Fatal(err)
				}
				pool.check()
				if delivered != n {
					t.Fatalf("delivered %d", delivered)
				}
			})
		}
	}
}
func TestParallelReceiveDelayedWorkers(t *testing.T) {
	r, client, peer := receiveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active, maxActive, calls atomic.Int32
	var committed []int
	s := &ESPTransportServer{Registry: r, ReceiveWorkers: 4, Conn: newPipelineConn(0)}
	s.HandleDecrypted = func(_ context.Context, _ *Association, _ net.Addr, b []byte, _ uint8, _ time.Time) (ESPPacketResult, error) {
		committed = append(committed, int(b[0]))
		return ESPPacketResult{}, nil
	}
	pool := newCountedPipelinePool(t)
	p := s.newReceivePipeline(ctx, cancel, pool.release, func(espDelivery) error { t.Fatal("unexpected dispatch"); return nil })
	p.crypto = func(packet *ESPReceive) {
		n := active.Add(1)
		for old := maxActive.Load(); n > old; old = maxActive.Load() {
			if maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(time.Duration((calls.Add(1)*37)%11) * 100 * time.Microsecond)
		packet.Authenticate()
		active.Add(-1)
	}
	for i := 0; i < 100; i++ {
		wire, _ := client.Seal([]byte{byte(i)}, 17)
		b, _ := pool.acquire(len(wire))
		copy(b.Bytes(), wire)
		packet, err := r.Precheck(peer, b.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := p.submit(packet, peer, time.Now(), b); err != nil {
			t.Fatal(err)
		}
	}
	p.closeAndWait()
	pool.check()
	if err := p.failure(); err != nil {
		t.Fatal(err)
	}
	if maxActive.Load() < 2 {
		t.Fatal("no within-SA parallelism")
	}
	if len(committed) != 100 {
		t.Fatal(len(committed))
	}
	for i, n := range committed {
		if i != n {
			t.Fatal("reordered")
		}
	}
}

func TestParallelReceiveFullWindowCancellation(t *testing.T) {
	r, client, peer := receiveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &ESPTransportServer{Registry: r, ReceiveWorkers: 4, Conn: newPipelineConn(0)}
	s.HandleDecrypted = func(context.Context, *Association, net.Addr, []byte, uint8, time.Time) (ESPPacketResult, error) {
		t.Error("cancelled work delivered")
		return ESPPacketResult{}, nil
	}
	pool := newCountedPipelinePool(t)
	p := s.newReceivePipeline(ctx, cancel, pool.release, func(espDelivery) error { return nil })
	gate := make(chan struct{})
	p.crypto = func(packet *ESPReceive) { <-gate; packet.Authenticate() }
	makeWork := func() (*ESPReceive, *packetbuf.Buffer) {
		wire, _ := client.Seal([]byte{1}, 17)
		b, _ := pool.acquire(len(wire))
		copy(b.Bytes(), wire)
		packet, err := r.Precheck(peer, b.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return packet, b
	}
	for i := 0; i < ESPReceiveCapacity; i++ {
		packet, b := makeWork()
		if err := p.submit(packet, peer, time.Now(), b); err != nil {
			t.Fatal(err)
		}
	}
	packet, b := makeWork()
	submitted := make(chan error, 1)
	go func() { submitted <- p.submit(packet, peer, time.Now(), b) }()
	select {
	case err := <-submitted:
		t.Fatalf("full window did not block: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	if err := <-submitted; err == nil {
		t.Fatal("cancel did not interrupt submit")
	}
	pool.release(b)
	close(gate)
	p.closeAndWait()
	pool.check()
}
func TestParallelReceiveWorkerPanic(t *testing.T) {
	r, client, peer := receiveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &ESPTransportServer{Registry: r, ReceiveWorkers: 2, Conn: newPipelineConn(0)}
	pool := newCountedPipelinePool(t)
	p := s.newReceivePipeline(ctx, cancel, pool.release, func(espDelivery) error { return nil })
	p.crypto = func(*ESPReceive) { panic("injected crypto failure") }
	wire, _ := client.Seal([]byte{1}, 17)
	b, _ := pool.acquire(len(wire))
	copy(b.Bytes(), wire)
	packet, _ := r.Precheck(peer, b.Bytes())
	if err := p.submit(packet, peer, time.Now(), b); err != nil {
		t.Fatal(err)
	}
	p.closeAndWait()
	pool.check()
	if p.failure() == nil {
		t.Fatal("missing panic error")
	}
}
func TestPhasedReceiveRevocationBeforeCommit(t *testing.T) {
	for _, retire := range []string{"remove", "close", "replace"} {
		t.Run(retire, func(t *testing.T) {
			r, client, peer := receiveFixture(t)
			wire, _ := client.Seal([]byte{1}, 17)
			p, err := r.Precheck(peer, wire)
			if err != nil {
				t.Fatal(err)
			}
			switch retire {
			case "remove":
				r.Remove(p.association.inboundSPI)
			case "close":
				r.Close()
			case "replace":
				if err := r.Install(peer, testESPPair(isakmp.EncapsulationNATTTransport)); err != nil {
					t.Fatal(err)
				}
			}
			p.Authenticate()
			if _, _, _, err := p.Commit(); err != ErrUnknownESP {
				t.Fatalf("revoked commit=%v", err)
			}
			if state := p.association.inbound.ReplayState(1); state.Highest != 0 {
				t.Fatal("revoked replay commit")
			}
		})
	}
}

func TestPhasedReceiveWindowMovesOnlyAtCommit(t *testing.T) {
	r, client, peer := receiveFixture(t)
	wire, _ := client.Seal([]byte{1}, 17)
	first, _ := r.Precheck(peer, wire)
	first.Authenticate()
	duplicate, _ := r.Precheck(peer, append([]byte(nil), wire...)) // already decrypted: do not authenticate this copy
	_ = duplicate
	var high []byte
	for i := 0; i < 1025; i++ {
		high, _ = client.Seal([]byte{1}, 17)
	}
	latest, _ := r.Precheck(peer, high)
	latest.Authenticate()
	if _, _, _, err := latest.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := first.Commit(); err != esp.ErrReplay {
		t.Fatalf("stale commit=%v", err)
	}
}
