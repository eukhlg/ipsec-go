package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/eukhlg/ipsec-go/protocol/esp"
	"github.com/eukhlg/ipsec-go/protocol/isakmp"
	"github.com/eukhlg/netio/packetbuf"
	"net"
	"strings"
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
	pair.ResponderCookie = isakmp.Cookie{9}
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
				s := &ESPTransportServer{Conn: conn, NATT: natt, Registry: r, ReceiveWorkers: workers}
				s.HandlePacket = func(context.Context, net.Addr, []byte, time.Time) (ESPPacketResult, error) {
					panic("legacy handler called")
				}
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
	for _, retire := range []string{"remove", "remove-ike", "close", "replace"} {
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
			case "remove-ike":
				r.RemoveIKE(isakmp.Cookie{9})
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

// An inline IKE packet can run maintenance before an older ESP worker returns.
// Its lifecycle revocation must win over the later crypto completion.
func TestParallelReceiveEarlyIKEMaintenanceRevokesPendingESP(t *testing.T) {
	r, client, peer := receiveFixture(t)
	control, err := isakmp.NewControlPlane(isakmp.ControlPlaneConfig{PreSharedKey: []byte("psk"), ResponderID: isakmp.Identification{IDType: isakmp.IDIPv4Address, Data: []byte{192, 0, 2, 1}}, Random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 1024)), HandshakeTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	transform := isakmp.Transform{Number: 1, ID: isakmp.TransformIKE, Attributes: []isakmp.Attribute{
		isakmp.TVAttribute(isakmp.AttributeP1Encryption, isakmp.EncryptionAESCBC), isakmp.TVAttribute(isakmp.AttributeP1Hash, isakmp.HashSHA1), isakmp.TVAttribute(isakmp.AttributeP1AuthMethod, isakmp.AuthPreSharedKey), isakmp.TVAttribute(isakmp.AttributeP1DHGroup, isakmp.DHGroup2), isakmp.TVAttribute(isakmp.AttributeP1KeyLength, 128)}}
	sa := isakmp.SecurityAssociation{DOI: isakmp.DOIIPsec, Situation: isakmp.SituationIdentityOnly, Proposals: []isakmp.Proposal{{Number: 1, ProtocolID: isakmp.ProtocolIKE, Transforms: []isakmp.Transform{transform}}}}
	request, err := (isakmp.Packet{InitiatorCookie: isakmp.Cookie{1}, Exchange: isakmp.ExchangeIdentityProtect, Payloads: []isakmp.Payload{sa}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	response, err := control.HandleDatagram(peer, request, time.Now().Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	header, err := isakmp.DecodePacket(response.Reply)
	if err != nil {
		t.Fatal(err)
	}
	r.RebindIKE(isakmp.Cookie{9}, header.ResponderCookie)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &ESPTransportServer{Conn: newPipelineConn(0), NATT: true, Registry: r, ReceiveWorkers: 2, ControlPlane: control}
	s.HandleDecrypted = func(context.Context, *Association, net.Addr, []byte, uint8, time.Time) (ESPPacketResult, error) {
		t.Error("retired ESP delivered")
		return ESPPacketResult{}, nil
	}
	maintained := false
	s.Lifecycle = func(_ context.Context, events []isakmp.LifecycleEvent) {
		for _, event := range events {
			if event.Type == isakmp.LifecycleExpireIKE {
				maintained = true
				r.RemoveIKE(event.ResponderCookie)
			}
		}
	}
	pool := newCountedPipelinePool(t)
	p := s.newReceivePipeline(ctx, cancel, pool.release, func(espDelivery) error { t.Error("retired dispatch"); return nil })
	started, resume := make(chan struct{}), make(chan struct{})
	p.crypto = func(packet *ESPReceive) { close(started); <-resume; packet.Authenticate() }
	wire, _ := client.Seal([]byte{1}, 17)
	b, _ := pool.acquire(len(wire))
	copy(b.Bytes(), wire)
	packet, _ := r.Precheck(peer, b.Bytes())
	if err := p.submit(packet, peer, time.Now(), b); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := s.processMessageDispatch(ctx, nil, peer, esp.EncapsulateNATTIKE([]byte{1}), func(func(context.Context) error) error { return nil }); err != nil {
		t.Fatal(err)
	}
	close(resume)
	p.closeAndWait()
	pool.check()
	if !maintained || control.SACount() != 0 || r.Count() != 0 {
		t.Fatal("inline IKE did not retire pending work")
	}
	if state := packet.association.inbound.ReplayState(1); state.Highest != 0 {
		t.Fatal("retired worker advanced replay")
	}
}

func TestParallelReceiveFullWindowResumesWithoutLoss(t *testing.T) {
	r, client, peer := receiveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	count := 0
	s := &ESPTransportServer{Registry: r, ReceiveWorkers: 4, Conn: newPipelineConn(0)}
	s.HandleDecrypted = func(context.Context, *Association, net.Addr, []byte, uint8, time.Time) (ESPPacketResult, error) {
		count++
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
	close(gate)
	if err := <-submitted; err != nil {
		t.Fatal(err)
	}
	p.closeAndWait()
	pool.check()
	if count != ESPReceiveCapacity+1 {
		t.Fatalf("lost tickets: %d", count)
	}
}

func TestParallelReceiveCancellationWhileCommitterBlocked(t *testing.T) {
	r, client, peer := receiveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &ESPTransportServer{Registry: r, ReceiveWorkers: 2, Conn: newPipelineConn(0)}
	s.HandleDecrypted = func(context.Context, *Association, net.Addr, []byte, uint8, time.Time) (ESPPacketResult, error) {
		return ESPPacketResult{Dispatch: func(context.Context) error { return nil }}, nil
	}
	entered := make(chan struct{})
	pool := newCountedPipelinePool(t)
	p := s.newReceivePipeline(ctx, cancel, pool.release, func(espDelivery) error { close(entered); <-ctx.Done(); return ctx.Err() })
	wire, _ := client.Seal([]byte{1}, 17)
	b, _ := pool.acquire(len(wire))
	copy(b.Bytes(), wire)
	packet, _ := r.Precheck(peer, b.Bytes())
	if err := p.submit(packet, peer, time.Now(), b); err != nil {
		t.Fatal(err)
	}
	pipelineWait(t, entered)
	cancel()
	p.closeAndWait()
	pool.check()
}

func TestDeliveryWatchdogReportsStallAndFullFIFO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	messages := make(chan string, 16)
	s := &ESPTransportServer{Conn: newPipelineConn(200)}
	s.Debugf = func(format string, _ ...any) {
		select {
		case messages <- format:
		default:
		}
	}
	s.HandlePacket = func(context.Context, net.Addr, []byte, time.Time) (ESPPacketResult, error) {
		return ESPPacketResult{Dispatch: func(ctx context.Context) error { <-ctx.Done(); return nil }}, nil
	}
	pool := newCountedPipelinePool(t)
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, pool.acquire, pool.release) }()
	callback, full := false, false
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for !callback || !full {
		select {
		case message := <-messages:
			if strings.Contains(message, "callback stalled") {
				callback = true
			}
			if strings.Contains(message, "FIFO full") {
				full = true
			}
		case <-deadline.C:
			cancel()
			<-done
			t.Fatal("watchdog did not report blocked delivery and FIFO")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	pool.check()
}
