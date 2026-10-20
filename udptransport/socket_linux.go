//go:build linux

package udptransport

import (
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"syscall"
)

func newBatchSocket(conn net.PacketConn) batchSocket {
	udp, ok := conn.(*net.UDPConn)
	if !ok || udp.RemoteAddr() != nil {
		return nil
	}
	addr, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	if addr.IP.To4() != nil {
		return ipv4.NewPacketConn(udp)
	}
	return ipv6.NewPacketConn(udp)
}
func messageTruncated(flags int) bool { return flags&syscall.MSG_TRUNC != 0 }
