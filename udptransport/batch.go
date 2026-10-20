// Package udptransport provides message batching without changing UDP framing.
package udptransport

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/ipv6"
)

// BatchSize bounds both queue draining and receive storage.
const BatchSize = 32

// Message borrows caller-owned storage until the operation returns. N and
// Truncated are receive outputs. Each message is one UDP datagram.
type Message struct {
	Payload   []byte
	Peer      net.Addr
	N         int
	Truncated bool
}

type batchSocket interface {
	ReadBatch([]ipv6.Message, int) (int, error)
	WriteBatch([]ipv6.Message, int) (int, error)
}

// Conn leaves deadlines and socket ownership with its caller. One reader and
// one writer may operate concurrently. Metadata is kept independently per side.
type Conn struct {
	conn                        net.PacketConn
	batch                       batchSocket
	readFallback, writeFallback atomic.Bool
	rx, tx                      [BatchSize]ipv6.Message
	rxBuffers, txBuffers        [BatchSize][1][]byte
}

func New(conn net.PacketConn) *Conn {
	c := &Conn{conn: conn, batch: newBatchSocket(conn)}
	for i := range c.rx {
		c.rx[i].Buffers = c.rxBuffers[i][:]
		c.tx[i].Buffers = c.txBuffers[i][:]
	}
	return c
}
func (c *Conn) BatchSize() int {
	if c.batch == nil {
		return 1
	}
	return BatchSize
}
func unsupported(err error) bool {
	return errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP)
}

// Read receives into independent caller buffers. Only entries before n are
// valid, including when an error accompanies progress. Truncated entries must
// be discarded. The buffers cannot be reused until their consumers finish.
func (c *Conn) Read(messages []Message) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	if len(messages) > BatchSize {
		messages = messages[:BatchSize]
	}
	if c.batch != nil && !c.readFallback.Load() {
		for i := range messages {
			c.rx[i].Buffers[0] = messages[i].Payload
			c.rx[i].N = 0
			c.rx[i].Flags = 0
			c.rx[i].Addr = nil
		}
		n, err := c.batch.ReadBatch(c.rx[:len(messages)], 0)
		if n < 0 && err != nil {
			n = 0
		} // x/net may return -1 after EAGAIN followed by a deadline.
		if n < 0 || n > len(messages) {
			for i := range messages {
				c.rx[i].Buffers[0] = nil
				c.rx[i].Addr = nil
			}
			return 0, io.ErrUnexpectedEOF
		}
		for i := 0; i < n; i++ {
			m := c.rx[i]
			messages[i].N = m.N
			messages[i].Peer = m.Addr
			messages[i].Truncated = messageTruncated(m.Flags) || m.N < 0 || m.N > len(messages[i].Payload)
		}
		for i := range messages {
			c.rx[i].Buffers[0] = nil
			c.rx[i].Addr = nil
		}
		if n != 0 || !unsupported(err) {
			if n == 0 && err == nil {
				err = io.ErrNoProgress
			}
			return n, err
		}
		c.readFallback.Store(true)
	}
	m := &messages[0]
	var err error
	if udp, ok := c.conn.(*net.UDPConn); ok {
		var flags int
		m.N, _, flags, m.Peer, err = udp.ReadMsgUDP(m.Payload, nil)
		m.Truncated = messageTruncated(flags)
	} else {
		m.N, m.Peer, err = c.conn.ReadFrom(m.Payload)
		// PacketConn cannot expose MSG_TRUNC; conservatively reject a full buffer.
		m.Truncated = m.N == len(m.Payload)
	}
	m.Truncated = m.Truncated || m.N < 0 || m.N > len(m.Payload)
	if err != nil {
		return 0, err
	}
	return 1, nil
}

// Write returns the successfully transmitted prefix. The caller must advance
// by n before retrying; an error or zero progress must never cause a busy loop.
// This method never releases or retains payload storage.
func (c *Conn) Write(messages []Message) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}
	if len(messages) > BatchSize {
		messages = messages[:BatchSize]
	}
	if c.batch != nil && !c.writeFallback.Load() {
		for i, m := range messages {
			c.tx[i].Buffers[0] = m.Payload
			c.tx[i].Addr = m.Peer
		}
		n, err := c.batch.WriteBatch(c.tx[:len(messages)], 0)
		for i := range messages {
			c.tx[i].Buffers[0] = nil
			c.tx[i].Addr = nil
		}
		if n < 0 && err != nil {
			n = 0
		}
		if n < 0 || n > len(messages) {
			return 0, io.ErrShortWrite
		}
		if n != 0 || !unsupported(err) {
			if n == 0 && err == nil {
				err = io.ErrNoProgress
			}
			return n, err
		}
		c.writeFallback.Store(true)
	}
	m := messages[0]
	n, err := c.conn.WriteTo(m.Payload, m.Peer)
	if err != nil {
		return 0, err
	}
	if n != len(m.Payload) {
		return 0, io.ErrShortWrite
	}
	return 1, nil
}
