//go:build !linux

package udptransport

import "net"

func newBatchSocket(net.PacketConn) batchSocket { return nil }
