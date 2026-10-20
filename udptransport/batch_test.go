package udptransport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
)

type scriptedBatch struct {
	writes func([]ipv6.Message) (int, error)
	reads  func([]ipv6.Message) (int, error)
}

func (s scriptedBatch) WriteBatch(m []ipv6.Message, _ int) (int, error) { return s.writes(m) }
func (s scriptedBatch) ReadBatch(m []ipv6.Message, _ int) (int, error)  { return s.reads(m) }

func listen(t testing.TB, network string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func TestLoopbackMessages(t *testing.T) {
	for _, size := range []int{1, 8, 32} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			a, b, s := listen(t, "udp4"), listen(t, "udp4"), listen(t, "udp4")
			tx := New(s)
			messages := make([]Message, size)
			for i := range messages {
				peer := a.LocalAddr()
				if i%2 == 1 {
					peer = b.LocalAddr()
				}
				messages[i] = Message{Payload: []byte{byte(i), 42}, Peer: peer}
			}
			for start := 0; start < size; {
				n, err := tx.Write(messages[start:])
				if err != nil || n == 0 {
					t.Fatalf("%d %v", n, err)
				}
				start += n
			}
			for parity, c := range []*net.UDPConn{a, b} {
				rx := New(c)
				slots := make([]Message, BatchSize)
				for i := range slots {
					slots[i].Payload = make([]byte, 100)
				}
				c.SetReadDeadline(time.Now().Add(time.Second))
				next := parity
				for next < size {
					n, err := rx.Read(slots)
					if err != nil || n == 0 {
						t.Fatalf("%d %v", n, err)
					}
					for i := 0; i < n; i++ {
						m := slots[i]
						if m.Truncated || !bytes.Equal(m.Payload[:m.N], []byte{byte(next), 42}) || m.Peer.String() != s.LocalAddr().String() {
							t.Fatalf("message %+v next %d", m, next)
						}
						next += 2
					}
				}
			}
		})
	}
}
func TestTruncationAndClosure(t *testing.T) {
	rx, tx := listen(t, "udp4"), listen(t, "udp4")
	c := New(rx)
	tx.WriteToUDP(make([]byte, 100), rx.LocalAddr().(*net.UDPAddr))
	m := []Message{{Payload: make([]byte, 4)}}
	n, err := c.Read(m)
	if err != nil || n != 1 || !m[0].Truncated {
		t.Fatalf("%d %v %+v", n, err, m)
	}
	rx.Close()
	if _, err := c.Read(m); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := c.Write([]Message{{Payload: []byte{1}, Peer: tx.LocalAddr()}}); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
func TestPartialProgressAndZero(t *testing.T) {
	c := New(listen(t, "udp4"))
	calls := 0
	c.batch = scriptedBatch{writes: func(m []ipv6.Message) (int, error) {
		calls++
		if len(m) != 3 || m[0].Buffers[0][0] != 1 {
			t.Fatal("bad messages")
		}
		return 2, nil
	}}
	m := []Message{{Payload: []byte{1}}, {Payload: []byte{2}}, {Payload: []byte{3}}}
	n, err := c.Write(m)
	if n != 2 || err != nil || calls != 1 {
		t.Fatalf("%d %v", n, err)
	}
	c.batch = scriptedBatch{writes: func([]ipv6.Message) (int, error) { return 0, nil }}
	if _, err = c.Write(m); !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
	c.batch = scriptedBatch{writes: func([]ipv6.Message) (int, error) { return 1, io.ErrClosedPipe }}
	if n, err = c.Write(m); n != 1 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("%d %v", n, err)
	}
}
func TestReadValidPrefixAndLengths(t *testing.T) {
	c := New(listen(t, "udp4"))
	c.batch = scriptedBatch{reads: func(m []ipv6.Message) (int, error) { m[0].N = 3; m[1].N = 9; return 2, io.EOF }}
	slots := []Message{{Payload: make([]byte, 4)}, {Payload: make([]byte, 4)}, {Payload: make([]byte, 4), N: 99}}
	n, err := c.Read(slots)
	if n != 2 || err != io.EOF || slots[0].Truncated || !slots[1].Truncated || slots[2].N != 99 {
		t.Fatalf("%d %v %+v", n, err, slots)
	}
}
func BenchmarkUDPTransport(b *testing.B) {
	for _, size := range []int{64, 1400} {
		for _, batch := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/batch=%t", size, batch), func(b *testing.B) {
				rx, tx := listen(b, "udp4"), listen(b, "udp4")
				writer := New(tx)
				reader := New(rx)
				if !batch {
					writer.batch = nil
					reader.batch = nil
				}
				stop := make(chan struct{})
				done := make(chan struct{})
				go func() {
					defer close(done)
					slots := make([]Message, BatchSize)
					for i := range slots {
						slots[i].Payload = make([]byte, 65535)
					}
					for {
						var err error
						if batch {
							_, err = reader.Read(slots)
						} else {
							_, _, err = rx.ReadFrom(slots[0].Payload)
						}
						if err != nil {
							return
						}
						select {
						case <-stop:
							return
						default:
						}
					}
				}()
				messages := make([]Message, BatchSize)
				for i := range messages {
					messages[i] = Message{Payload: make([]byte, size), Peer: rx.LocalAddr()}
				}
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; {
					limit := min(BatchSize, b.N-i)
					var n int
					var err error
					if batch {
						n, err = writer.Write(messages[:limit])
					} else {
						_, err = tx.WriteTo(messages[0].Payload, messages[0].Peer)
						n = 1
					}
					if err != nil {
						b.Fatal(err)
					}
					i += n
				}
				b.StopTimer()
				close(stop)
				rx.Close()
				<-done
			})
		}
	}
}

func TestUnsupportedBatchFallsBackOnce(t *testing.T) {
	rx, tx := listen(t, "udp4"), listen(t, "udp4")
	c := New(tx)
	calls := 0
	c.batch = scriptedBatch{writes: func([]ipv6.Message) (int, error) { calls++; return 0, syscall.ENOSYS }}
	for i := 0; i < 2; i++ {
		if n, err := c.Write([]Message{{Payload: []byte{byte(i)}, Peer: rx.LocalAddr()}}); n != 1 || err != nil {
			t.Fatalf("%d %v", n, err)
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	reader := New(rx)
	calls = 0
	reader.batch = scriptedBatch{reads: func([]ipv6.Message) (int, error) { calls++; return 0, syscall.EOPNOTSUPP }}
	for i := 0; i < 2; i++ {
		m := []Message{{Payload: make([]byte, 10)}}
		n, err := reader.Read(m)
		if n != 1 || err != nil || m[0].Payload[0] != byte(i) {
			t.Fatalf("%d %v", n, err)
		}
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}
func TestIPv6AndDualStack(t *testing.T) {
	for _, network := range []string{"udp6", "udp"} {
		t.Run(network, func(t *testing.T) {
			rx, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IPv6unspecified})
			if err != nil {
				t.Skip(err)
			}
			defer rx.Close()
			tx, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IPv6unspecified})
			if err != nil {
				t.Skip(err)
			}
			defer tx.Close()
			addr := rx.LocalAddr().(*net.UDPAddr)
			peer := &net.UDPAddr{IP: net.IPv6loopback, Port: addr.Port}
			writer, reader := New(tx), New(rx)
			m := []Message{{Payload: []byte{1}, Peer: peer}, {Payload: []byte{2}, Peer: peer}}
			for len(m) > 0 {
				n, err := writer.Write(m)
				if err != nil {
					t.Fatal(err)
				}
				m = m[n:]
			}
			rx.SetReadDeadline(time.Now().Add(time.Second))
			next := byte(1)
			for next <= 2 {
				slots := []Message{{Payload: make([]byte, 10)}, {Payload: make([]byte, 10)}}
				n, err := reader.Read(slots)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < n; i++ {
					if slots[i].Payload[0] != next {
						t.Fatal("ordering")
					}
					next++
				}
			}
		})
	}
}

func TestDeadlineAndNegativeErrorCount(t *testing.T) {
	c := listen(t, "udp4")
	conn := New(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	n, err := conn.Read([]Message{{Payload: make([]byte, 100)}})
	var ne net.Error
	if n != 0 || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("deadline lost: %d %v", n, err)
	}
	conn.batch = scriptedBatch{reads: func([]ipv6.Message) (int, error) { return -1, syscall.ENOSYS }}
	c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	n, err = conn.Read([]Message{{Payload: make([]byte, 100)}})
	if n != 0 || !errors.As(err, &ne) || !ne.Timeout() || !conn.readFallback.Load() {
		t.Fatalf("fallback lost: %d %v", n, err)
	}
	conn.batch = scriptedBatch{writes: func([]ipv6.Message) (int, error) { return -1, io.ErrClosedPipe }}
	n, err = conn.Write([]Message{{Payload: []byte{1}}})
	if n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error lost: %d %v", n, err)
	}
}
